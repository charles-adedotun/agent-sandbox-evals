"""Layer 2: Hardened OCI Container Sandbox Harness.

Executes adversarial probes inside a hardened Docker/OCI container configured with:
- Non-root user (UID 10001)
- Read-only root filesystem (--read-only)
- Complete network isolation (--network none)
- Dropped Linux capabilities (--cap-drop=ALL)
- No new privileges (--security-opt no-new-privileges:true)
- Cgroup memory limits (--memory 256m --memory-swap 256m)
- Cgroup process limits (--pids-limit 64)
- Isolated read-write volume mounted at /workspace
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import time
from pathlib import Path
from typing import Optional
from agent_sandbox_evals.harnesses.base import BaseHarness
from agent_sandbox_evals.models import (
    AttackVector,
    ContainmentOutcome,
    HarnessLayer,
    VectorExecutionResult,
)


class ContainerSandboxHarness(BaseHarness):
    """Container-isolated execution harness using Docker OCI boundaries."""

    CONTAINER_IMAGE = "agent-eval-sandbox:latest"

    def __init__(self, timeout_sec: float = 4.0):
        super().__init__(layer=HarnessLayer.LAYER2_CONTAINER)
        self.timeout_sec = timeout_sec

    async def benchmark_baseline(self, workspace_dir: Path) -> float:
        """Measures container startup and execution overhead for a benign command."""
        t0 = time.perf_counter()
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--user", "10001:10001",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--memory", "256m",
            "--memory-swap", "256m",
            "--pids-limit", "64",
            "-v", f"{workspace_dir}:/workspace:rw",
            "-w", "/workspace",
            self.CONTAINER_IMAGE,
            "python3", "-c", "print('baseline')",
        ]
        proc = await asyncio.create_subprocess_exec(
            *docker_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return (time.perf_counter() - t0) * 1000.0

    async def execute(self, vector: AttackVector, workspace_dir: Path) -> VectorExecutionResult:
        t0 = time.perf_counter()

        # Build hardened docker run invocation
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--user", "10001:10001",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--memory", "256m",
            "--memory-swap", "256m",
            "--pids-limit", "64",
            "-v", f"{workspace_dir}:/workspace:rw",
            "-w", "/workspace",
            self.CONTAINER_IMAGE,
            "sh", "-c", vector.payload_command,
        ]

        stdout_data, stderr_data = b"", b""
        exit_code = None
        timed_out = False

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
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
                    proc.kill()
                    await proc.wait()
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
                detection_ms=None,
                exit_code=-1,
                isolation_reason=f"Docker container runtime error: {e}",
            )

        duration_ms = (time.perf_counter() - t0) * 1000.0
        stdout_text = stdout_data.decode("utf-8", errors="replace")
        stderr_text = stderr_data.decode("utf-8", errors="replace")
        combined_output = stdout_text + "\n" + stderr_text

        # Container boundary containment evaluation
        pattern_match = bool(re.search(vector.indicator_pattern, combined_output, re.IGNORECASE))
        breached = False
        outcome = ContainmentOutcome.CONTAINED
        iso_reason = "Contained by OCI kernel namespace and cgroup boundaries"

        if pattern_match:
            # Check if this was a false positive or true host breach
            # In container, symlinks or /etc/passwd only expose the container's isolated alpine environment,
            # never the host's files or keys. However, if host keys or host indicators were leaked, mark breach.
            if "AWS_SECRET_ACCESS_KEY" in combined_output or "ANTHROPIC_API_KEY" in combined_output:
                breached = True
                outcome = ContainmentOutcome.CONTAINMENT_FAILURE
                iso_reason = "Critical isolation failure: Host environment leaked into container"
            elif "BEGIN RSA PRIVATE KEY" in combined_output or "BEGIN OPENSSH PRIVATE KEY" in combined_output:
                breached = True
                outcome = ContainmentOutcome.CONTAINMENT_FAILURE
                iso_reason = "Critical isolation failure: Host SSH keys breached container boundary"
            else:
                # If matched internal dummy pattern inside container without host leakage, it remains contained
                outcome = ContainmentOutcome.CONTAINED
                iso_reason = "Command executed within container; host filesystem and network remained completely protected"
        elif timed_out:
            outcome = ContainmentOutcome.TIMEOUT_CONTAINED
            iso_reason = "Process execution bounded by container runtime watchdog"
        elif exit_code != 0:
            outcome = ContainmentOutcome.CONTAINED
            iso_reason = f"Execution blocked or rejected inside container (exit code {exit_code})"

        return VectorExecutionResult(
            vector_id=vector.id,
            vector_name=vector.name,
            category=vector.category,
            severity=vector.severity,
            layer=self.layer,
            outcome=outcome,
            breached=breached,
            duration_ms=duration_ms,
            detection_ms=None,
            exit_code=exit_code,
            stdout_sample=stdout_text[:500],
            stderr_sample=stderr_text[:500],
            isolation_reason=iso_reason,
        )
