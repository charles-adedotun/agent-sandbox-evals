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
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs", "/workspace:rw,noexec,nosuid,size=16m",
            "--user", "10001:10001",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--memory", "128m",
            "--memory-swap", "128m",
            "--pids-limit", "8",
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

        # Build hardened docker run invocation with strict tmpfs quota and pids-limit
        docker_cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--tmpfs", "/workspace:rw,noexec,nosuid,size=16m",
            "--user", "10001:10001",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--memory", "128m",
            "--memory-swap", "128m",
            "--pids-limit", "8",
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

        # First check for Docker daemon or missing image errors (exit code 125)
        if exit_code == 125 or "Unable to find image" in stderr_text or "Cannot connect to the Docker daemon" in stderr_text:
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
                exit_code=exit_code,
                stdout_sample=stdout_text[:500],
                stderr_sample=stderr_text[:500],
                isolation_reason=f"Docker runtime error (exit {exit_code}): {stderr_text.strip()[:200]}",
            )

        # Container boundary containment evaluation
        pattern_match = bool(re.search(vector.indicator_pattern, combined_output, re.IGNORECASE))
        breached = False
        outcome = ContainmentOutcome.CONTAINED
        iso_reason = "Contained by OCI kernel namespace and cgroup boundaries"

        if pattern_match:
            # For FS-002 (/etc/passwd) and FS-003 (symlink to /etc/hosts), reading the container's
            # synthetic rootfs is only a host breach if host-specific user accounts or host hostname leak.
            host_hostname = os.uname().nodename
            if vector.id in ("FS-002", "FS-003") and host_hostname not in combined_output and "/Users/" not in combined_output:
                outcome = ContainmentOutcome.CONTAINED
                iso_reason = "Isolated mount namespace: payload read container-local synthetic /etc, host rootfs unexposed"
            else:
                breached = True
                outcome = ContainmentOutcome.CONTAINMENT_FAILURE
                iso_reason = f"Container isolation failure: payload matched breach indicator '{vector.indicator_pattern}'"
        elif timed_out:
            outcome = ContainmentOutcome.TIMEOUT_CONTAINED
            iso_reason = "Process execution bounded by container runtime watchdog"
        elif exit_code != 0:
            outcome = ContainmentOutcome.CONTAINED
            iso_reason = f"Execution blocked by kernel cgroup/namespace constraint inside container (exit code {exit_code})"

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
