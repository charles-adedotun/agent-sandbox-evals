"""Async benchmark runner executing attack matrix across isolation harness layers."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

from agent_sandbox_evals.harnesses.base import BaseHarness
from agent_sandbox_evals.harnesses.layer0_host import RawHostHarness
from agent_sandbox_evals.harnesses.layer1_sanitized import SanitizedMCPHarness
from agent_sandbox_evals.harnesses.layer2_container import ContainerSandboxHarness
from agent_sandbox_evals.models import (
    AttackCategory,
    AttackVector,
    BenchmarkReport,
    ContainmentOutcome,
    HarnessLayer,
    LayerSummary,
    VectorExecutionResult,
)
from agent_sandbox_evals.vectors.matrix import get_all_vectors


class BenchmarkRunner:
    """Orchestrates async evaluation across Layer 0, Layer 1, and Layer 2 harnesses."""

    def __init__(
        self,
        vectors: Optional[List[AttackVector]] = None,
        layers: Optional[List[HarnessLayer]] = None,
        concurrency: int = 1,  # Sequential execution guarantees clean timing and zero port collisions
        progress_callback: Optional[Callable[[VectorExecutionResult, int, int], None]] = None,
    ):
        self.vectors = vectors or get_all_vectors()
        self.target_layers = layers or [
            HarnessLayer.LAYER0_HOST,
            HarnessLayer.LAYER1_SANITIZED,
            HarnessLayer.LAYER2_CONTAINER,
        ]
        self.concurrency = concurrency
        self.progress_callback = progress_callback
        self.harnesses: Dict[HarnessLayer, BaseHarness] = {
            HarnessLayer.LAYER0_HOST: RawHostHarness(),
            HarnessLayer.LAYER1_SANITIZED: SanitizedMCPHarness(),
            HarnessLayer.LAYER2_CONTAINER: ContainerSandboxHarness(),
        }

    def _setup_mock_workspace(self, root_temp_dir: Path) -> Path:
        """Sets up a realistic sandbox workspace with simulated dummy files to test path traversal."""
        # Create hierarchy: root_temp_dir / outer / workspace
        outer_dir = root_temp_dir / "outer"
        outer_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy outer secrets to test directory traversal detection
        dummy_ssh = outer_dir / ".ssh"
        dummy_ssh.mkdir(parents=True, exist_ok=True)
        (dummy_ssh / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0mockkey...\n-----END RSA PRIVATE KEY-----\n")

        dummy_aws = outer_dir / ".aws"
        dummy_aws.mkdir(parents=True, exist_ok=True)
        (dummy_aws / "credentials").write_text("[default]\naws_access_key_id = AKIAIOSFODNN7BREACHED\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYBREACHEDKEY\n")

        (outer_dir / ".env").write_text("DATABASE_URL=postgres://dbuser:pass123@prod.db.internal:5432/main\nANTHROPIC_API_KEY=sk-ant-dummy-traversal-breach\n")

        workspace_dir = outer_dir / "sandbox_workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        return workspace_dir

    async def run(self) -> BenchmarkReport:
        """Executes full benchmark across configured layers and vectors."""
        benchmark_id = f"bench-{uuid.uuid4().hex[:8]}"
        all_results: List[VectorExecutionResult] = []
        layer_summaries: Dict[HarnessLayer, LayerSummary] = {}
        total_evaluations = len(self.target_layers) * len(self.vectors)
        evaluation_counter = 0

        temp_base = Path(tempfile.mkdtemp(prefix="agent_sandbox_eval_"))

        try:
            workspace_dir = self._setup_mock_workspace(temp_base)

            for layer_enum in self.target_layers:
                harness = self.harnesses[layer_enum]

                # Step 1: Measure baseline execution overhead for this harness
                try:
                    baseline_latency_ms = await harness.benchmark_baseline(workspace_dir)
                except Exception:
                    baseline_latency_ms = 0.0

                layer_results: List[VectorExecutionResult] = []

                # Step 2: Execute vectors
                for vector in self.vectors:
                    evaluation_counter += 1
                    try:
                        res = await harness.execute(vector, workspace_dir)
                    except Exception as e:
                        res = VectorExecutionResult(
                            vector_id=vector.id,
                            vector_name=vector.name,
                            category=vector.category,
                            severity=vector.severity,
                            layer=layer_enum,
                            outcome=ContainmentOutcome.ERROR,
                            breached=False,
                            duration_ms=0.0,
                            isolation_reason=f"Execution error: {e}",
                        )

                    layer_results.append(res)
                    all_results.append(res)

                    if self.progress_callback:
                        self.progress_callback(res, evaluation_counter, total_evaluations)

                # Step 3: Compute layer summary statistics
                total_vecs = len(layer_results)
                blocked_cnt = sum(1 for r in layer_results if r.outcome == ContainmentOutcome.BLOCKED)
                contained_cnt = sum(
                    1 for r in layer_results
                    if r.outcome in (ContainmentOutcome.CONTAINED, ContainmentOutcome.TIMEOUT_CONTAINED)
                )
                failure_cnt = sum(1 for r in layer_results if r.breached)
                error_cnt = sum(1 for r in layer_results if r.outcome == ContainmentOutcome.ERROR)

                cfr_pct = (failure_cnt / total_vecs * 100.0) if total_vecs > 0 else 0.0
                csr_pct = 100.0 - cfr_pct

                detection_times = [r.detection_ms for r in layer_results if r.detection_ms is not None]
                avg_detect_ms = (sum(detection_times) / len(detection_times)) if detection_times else 0.0

                execution_times = [r.duration_ms for r in layer_results]
                avg_exec_ms = (sum(execution_times) / len(execution_times)) if execution_times else 0.0

                layer_summaries[layer_enum] = LayerSummary(
                    layer=layer_enum,
                    layer_name=layer_enum.display_name,
                    total_vectors=total_vecs,
                    blocked_count=blocked_cnt,
                    contained_count=contained_cnt,
                    failure_count=failure_cnt,
                    error_count=error_cnt,
                    cfr_pct=round(cfr_pct, 2),
                    csr_pct=round(csr_pct, 2),
                    avg_detection_ms=round(avg_detect_ms, 2),
                    avg_execution_ms=round(avg_exec_ms, 2),
                    baseline_latency_ms=round(baseline_latency_ms, 2),
                )

        finally:
            shutil.rmtree(temp_base, ignore_errors=True)

        # Step 4: Compute category breakdown CFR
        category_cfr: Dict[AttackCategory, Dict[HarnessLayer, float]] = {}
        for cat in AttackCategory:
            category_cfr[cat] = {}
            for layer_enum in self.target_layers:
                cat_results = [r for r in all_results if r.layer == layer_enum and r.category == cat]
                if cat_results:
                    cat_breaches = sum(1 for r in cat_results if r.breached)
                    category_cfr[cat][layer_enum] = round((cat_breaches / len(cat_results)) * 100.0, 1)
                else:
                    category_cfr[cat][layer_enum] = 0.0

        return BenchmarkReport(
            benchmark_id=benchmark_id,
            environment_info={
                "os": os.uname().sysname,
                "release": os.uname().release,
                "machine": os.uname().machine,
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
                "docker_image": ContainerSandboxHarness.CONTAINER_IMAGE,
            },
            layers=layer_summaries,
            results=all_results,
            category_cfr=category_cfr,
        )
