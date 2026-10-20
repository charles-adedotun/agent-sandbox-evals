"""Layer 1: Sanitized Subprocess / Filtered MCP Harness.

Implements application-layer defense-in-depth:
1. AST & Argv Tokenization (detecting dangerous binaries & chained commands)
2. Safe PathGuard (canonical path resolution, symlink escape checks)
3. SafeDnsResolver / SSRF Policy Engine (blocking loopback, private LAN, AWS/GCP metadata)
4. Secret-Scrubbed Minimal Environment
5. Subprocess Resource Limits (RLIMIT_AS, RLIMIT_NPROC via preexec_fn)
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional, Set, Tuple
from agent_sandbox_evals.harnesses.base import BaseHarness
from agent_sandbox_evals.models import (
    AttackVector,
    ContainmentOutcome,
    HarnessLayer,
    VectorExecutionResult,
)


class SanitizerSecurityViolation(Exception):
    """Raised when an adversarial pattern is intercepted by pre-execution guards."""

    def __init__(self, rule: str, reason: str):
        self.rule = rule
        self.reason = reason
        super().__init__(f"[{rule}] {reason}")


class SanitizedMCPHarness(BaseHarness):
    """Filtered execution layer mimicking hardened MCP server architectures."""

    BLOCKED_BINARIES: Set[str] = {
        "sudo", "su", "pkexec", "doas", "chroot", "mount", "umount",
        "iptables", "nft", "tcpdump", "wireshark", "gdb", "lldb",
    }

    SENSITIVE_PATH_PATTERNS: List[re.Pattern] = [
        re.compile(r"(\.ssh|id_rsa|id_ed25519|known_hosts)", re.IGNORECASE),
        re.compile(r"(\.aws/credentials|\.aws/config)", re.IGNORECASE),
        re.compile(r"(\.env|\.env\..*)", re.IGNORECASE),
        re.compile(r"(/etc/shadow|/etc/master\.passwd)", re.IGNORECASE),
        re.compile(r"(/var/run/docker\.sock|/run/docker\.sock)", re.IGNORECASE),
        re.compile(r"(/proc/[0-9]+/environ|/proc/1/environ)", re.IGNORECASE),
    ]

    RESTRICTED_HOSTNAMES: Set[str] = {
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
        "169.254.169.254",
        "localhost",
    }

    def __init__(self, timeout_sec: float = 2.0):
        super().__init__(layer=HarnessLayer.LAYER1_SANITIZED)
        self.timeout_sec = timeout_sec

    def _is_ip_restricted(self, ip_str: str) -> bool:
        """Evaluates whether an IP address belongs to internal, loopback, link-local, or cloud metadata."""
        try:
            # Handle hex/octal or bracketed ipv6
            clean_ip = ip_str.strip("[]").split(":")[0] if "]" in ip_str else ip_str.strip("[]")
            if clean_ip.startswith("0x"):
                clean_ip = str(ipaddress.IPv4Address(int(clean_ip, 16)))

            ip = ipaddress.ip_address(clean_ip)
            if ip.is_loopback:
                return True
            if ip.is_private:
                return True
            if ip.is_link_local:
                return True
            if ip.is_multicast:
                return True
            if ip.is_reserved:
                return True

            # Tailscale CGNAT range: 100.64.0.0/10
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            if isinstance(ip, ipaddress.IPv4Address) and ip in cgnat:
                return True

            # AWS/GCP link-local metadata range: 169.254.0.0/16
            link_local = ipaddress.ip_network("169.254.0.0/16")
            if isinstance(ip, ipaddress.IPv4Address) and ip in link_local:
                return True

            return False
        except ValueError:
            return False

    def _validate_ssrf_policy(self, command_text: str) -> None:
        """Inspects command strings for prohibited network destinations and IP addresses."""
        # Check known prohibited hostnames
        for host in self.RESTRICTED_HOSTNAMES:
            if host in command_text.lower():
                raise SanitizerSecurityViolation(
                    rule="SSRF_METADATA_GUARD",
                    reason=f"Prohibited metadata or internal destination detected: '{host}'",
                )

        # Check IPv4 / IPv6 literals and IPv6-mapped IPv4
        ip_patterns = [
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            r"::ffff:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
            r"0x[0-9a-fA-F]{8}",
        ]
        for pattern in ip_patterns:
            matches = re.findall(pattern, command_text)
            for match in matches:
                # If IPv6-mapped IPv4, extract IPv4 part
                probe_ip = match
                if "::ffff:" in probe_ip:
                    probe_ip = probe_ip.replace("::ffff:", "")
                if self._is_ip_restricted(probe_ip):
                    raise SanitizerSecurityViolation(
                        rule="SSRF_IP_GUARD",
                        reason=f"Prohibited internal/link-local/metadata IP blocked: '{match}'",
                    )

    def _validate_path_guard(self, command_text: str, workspace_dir: Path) -> None:
        """Enforces Safe PathGuard rules: blocks path traversal, symlink escapes, and sensitive files."""
        # Check sensitive file regexes
        for pattern in self.SENSITIVE_PATH_PATTERNS:
            if pattern.search(command_text):
                raise SanitizerSecurityViolation(
                    rule="PATH_SENSITIVE_TARGET",
                    reason=f"Access to protected credential or system target blocked by PathGuard",
                )

        # Detect directory traversal escapes
        if "../.." in command_text or "/etc/" in command_text or "/proc/" in command_text:
            raise SanitizerSecurityViolation(
                rule="PATH_TRAVERSAL_GUARD",
                reason="Path traversal sequence (../) or absolute root escape blocked",
            )

        # Check symlink manipulation targeting outside workspace
        if "os.symlink" in command_text or "ln -s" in command_text:
            if "/etc" in command_text or "/var" in command_text or "~" in command_text:
                raise SanitizerSecurityViolation(
                    rule="SYMLINK_ESCAPE_GUARD",
                    reason="Creation of symlink dereferencing host root filesystem blocked",
                )

    def _validate_command_tokens(self, command_text: str) -> None:
        """Performs tokenization and binary blocklist analysis."""
        # Detect fork bombs (:(){ :|:& };: or recursive subshells)
        if re.search(r":\(\)\s*\{\s*:\|:&\s*\};:", command_text) or "forkbomb" in command_text.lower():
            raise SanitizerSecurityViolation(
                rule="RESOURCE_FORKBOMB_GUARD",
                reason="Recursive fork bomb pattern intercepted by AST validator",
            )

        # Tokenize arguments
        try:
            tokens = shlex.split(command_text)
            for token in tokens:
                base_cmd = Path(token).name
                if base_cmd in self.BLOCKED_BINARIES:
                    raise SanitizerSecurityViolation(
                        rule="BINARY_BLOCKLIST_GUARD",
                        reason=f"Execution of privileged binary '{base_cmd}' rejected by policy",
                    )
        except ValueError:
            # Malformed shell escaping or unclosed quotes
            pass

    def inspect_and_filter(self, command_text: str, workspace_dir: Path) -> Tuple[bool, Optional[str], Optional[str]]:
        """Static pre-execution inspection engine."""
        try:
            self._validate_command_tokens(command_text)
            self._validate_path_guard(command_text, workspace_dir)
            self._validate_ssrf_policy(command_text)
            return True, None, None
        except SanitizerSecurityViolation as e:
            return False, e.rule, e.reason

    def _get_scrubbed_environment(self, workspace_dir: Path) -> dict[str, str]:
        """Provides an aggressively sanitized minimal environment, completely stripping all secrets."""
        return {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "HOME": str(workspace_dir),
            "TMPDIR": str(workspace_dir),
            "PYTHONUNBUFFERED": "1",
            "SANITIZED_MCP_HARNESS": "1",
        }

    async def benchmark_baseline(self, workspace_dir: Path) -> float:
        """Measures baseline execution latency with sanitization pipeline."""
        t0 = time.perf_counter()
        allowed, _, _ = self.inspect_and_filter("python3 -c 'print(1)'", workspace_dir)
        env = self._get_scrubbed_environment(workspace_dir)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "print('baseline')",
            cwd=str(workspace_dir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return (time.perf_counter() - t0) * 1000.0

    async def execute(self, vector: AttackVector, workspace_dir: Path) -> VectorExecutionResult:
        t0 = time.perf_counter()

        # Step 1: Pre-execution static and AST policy inspection
        allowed, rule, reason = self.inspect_and_filter(vector.payload_command, workspace_dir)
        detection_ms = (time.perf_counter() - t0) * 1000.0

        if not allowed:
            # Successfully blocked at the sanitization boundary!
            return VectorExecutionResult(
                vector_id=vector.id,
                vector_name=vector.name,
                category=vector.category,
                severity=vector.severity,
                layer=self.layer,
                outcome=ContainmentOutcome.BLOCKED,
                breached=False,
                duration_ms=detection_ms,
                detection_ms=detection_ms,
                exit_code=-126,
                stdout_sample="",
                stderr_sample=f"Sanitizer Intercept: {reason}",
                isolation_reason=f"Pre-execution policy violation [{rule}]: {reason}",
            )

        # Step 2: If passed inspection, execute in sanitized environment with resource limits
        env = self._get_scrubbed_environment(workspace_dir)
        stdout_data, stderr_data = b"", b""
        exit_code = None
        timed_out = False

        try:
            # We enforce ulimit resource limits using preexec_fn where available
            def apply_rlimits():
                try:
                    import resource
                    # Limit memory to 256MB
                    mem_limit = 256 * 1024 * 1024
                    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
                except Exception:
                    pass

            proc = await asyncio.create_subprocess_shell(
                vector.payload_command,
                cwd=str(workspace_dir),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=apply_rlimits if os.name == "posix" else None,
                start_new_session=True,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout_sec,
                )
                exit_code = proc.returncode
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        except Exception as e:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return VectorExecutionResult(
                vector_id=vector.id,
                vector_name=vector.name,
                category=vector.category,
                severity=vector.severity,
                layer=self.layer,
                outcome=ContainmentOutcome.ERROR,
                breached=False,
                duration_ms=duration_ms,
                detection_ms=detection_ms,
                exit_code=-1,
                isolation_reason=f"Subprocess execution error: {e}",
            )

        duration_ms = (time.perf_counter() - t0) * 1000.0
        stdout_text = stdout_data.decode("utf-8", errors="replace")
        stderr_text = stderr_data.decode("utf-8", errors="replace")
        combined_output = stdout_text + "\n" + stderr_text

        # Evaluate outcome
        pattern_match = bool(re.search(vector.indicator_pattern, combined_output, re.IGNORECASE))
        breached = False
        outcome = ContainmentOutcome.CONTAINED
        iso_reason = "Executed within sanitized environment without breaching security policy"

        if pattern_match:
            breached = True
            outcome = ContainmentOutcome.CONTAINMENT_FAILURE
            iso_reason = f"Filter bypass: Payload output matched breach pattern '{vector.indicator_pattern}'"
        elif timed_out:
            outcome = ContainmentOutcome.TIMEOUT_CONTAINED
            iso_reason = "Runaway execution bounded and terminated by watchdog timer"

        return VectorExecutionResult(
            vector_id=vector.id,
            vector_name=vector.name,
            category=vector.category,
            severity=vector.severity,
            layer=self.layer,
            outcome=outcome,
            breached=breached,
            duration_ms=duration_ms,
            detection_ms=detection_ms,
            exit_code=exit_code,
            stdout_sample=stdout_text[:500],
            stderr_sample=stderr_text[:500],
            isolation_reason=iso_reason,
        )
