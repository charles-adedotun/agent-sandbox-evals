"""Pydantic data models for agent-sandbox-evals benchmark suite."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    SSRF = "ssrf"
    FILESYSTEM = "filesystem"
    PRIVILEGE = "privilege"
    RESOURCE_DOS = "resource_dos"
    SECRET_LEAK = "secret_leak"

    @property
    def display_name(self) -> str:
        names = {
            AttackCategory.SSRF: "SSRF & Network Pivoting",
            AttackCategory.FILESYSTEM: "Filesystem & Traversal Breakout",
            AttackCategory.PRIVILEGE: "Privilege Escalation & SUID",
            AttackCategory.RESOURCE_DOS: "Resource Exhaustion & DoS",
            AttackCategory.SECRET_LEAK: "Secret & Environment Exfiltration",
        }
        return names.get(self, self.value)


class HarnessLayer(str, Enum):
    LAYER0_HOST = "layer0_host"
    LAYER1_SANITIZED = "layer1_sanitized"
    LAYER2_CONTAINER = "layer2_container"

    @property
    def display_name(self) -> str:
        names = {
            HarnessLayer.LAYER0_HOST: "Layer 0: Raw Host (Unsandboxed)",
            HarnessLayer.LAYER1_SANITIZED: "Layer 1: Sanitized Subprocess / Filtered MCP",
            HarnessLayer.LAYER2_CONTAINER: "Layer 2: Hardened OCI Container Sandbox",
        }
        return names.get(self, self.value)

    @property
    def short_name(self) -> str:
        names = {
            HarnessLayer.LAYER0_HOST: "Raw Host",
            HarnessLayer.LAYER1_SANITIZED: "Sanitized MCP",
            HarnessLayer.LAYER2_CONTAINER: "OCI Container",
        }
        return names.get(self, self.value)


class ContainmentOutcome(str, Enum):
    BLOCKED = "BLOCKED"  # Pre-execution static/policy filter intercepted and rejected
    CONTAINED = "CONTAINED"  # Executed inside boundary, but containment prevented breach
    CONTAINMENT_FAILURE = "BREACH"  # Isolation boundary failed; vector succeeded in breach
    TIMEOUT_CONTAINED = "TIMEOUT_CONTAINED"  # Resource watchdog killed runaway process
    ERROR = "ERROR"  # Test harness execution error


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackVector(BaseModel):
    id: str = Field(..., description="Unique vector ID e.g. SSRF-001, FS-002")
    name: str = Field(..., description="Human-readable vector name")
    category: AttackCategory = Field(..., description="Attack category")
    severity: Severity = Field(default=Severity.HIGH, description="Vulnerability severity level")
    description: str = Field(..., description="Details of the attack mechanism")
    payload_command: str = Field(..., description="Shell/CLI command executed to probe boundary")
    indicator_pattern: str = Field(..., description="Regex or substring indicating successful breakout")
    safe_simulation: bool = Field(
        default=True,
        description="Whether this probe uses safe bounds (e.g. bounded memory, controlled fork counter) to prevent host crash",
    )
    tags: List[str] = Field(default_factory=list)


class VectorExecutionResult(BaseModel):
    vector_id: str
    vector_name: str
    category: AttackCategory
    severity: Severity
    layer: HarnessLayer
    outcome: ContainmentOutcome
    breached: bool
    duration_ms: float
    detection_ms: Optional[float] = None
    exit_code: Optional[int] = None
    stdout_sample: str = ""
    stderr_sample: str = ""
    isolation_reason: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LayerSummary(BaseModel):
    layer: HarnessLayer
    layer_name: str
    total_vectors: int
    blocked_count: int
    contained_count: int
    failure_count: int
    error_count: int
    cfr_pct: float = Field(..., description="Containment Failure Rate %: breaches / total * 100")
    csr_pct: float = Field(..., description="Containment Success Rate %: 100 - CFR")
    avg_detection_ms: float = Field(..., description="Average pre-execution intercept latency in ms")
    avg_execution_ms: float = Field(..., description="Average total execution latency in ms")
    baseline_latency_ms: float = Field(default=0.0, description="Baseline execution overhead for benign task")


class BenchmarkReport(BaseModel):
    benchmark_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    environment_info: Dict[str, Any] = Field(default_factory=dict)
    layers: Dict[HarnessLayer, LayerSummary]
    results: List[VectorExecutionResult]
    category_cfr: Dict[AttackCategory, Dict[HarnessLayer, float]] = Field(default_factory=dict)
