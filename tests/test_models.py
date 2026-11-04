"""Unit tests for agent-sandbox-evals data models."""

from agent_sandbox_evals.models import (
    AttackCategory,
    AttackVector,
    ContainmentOutcome,
    HarnessLayer,
    LayerSummary,
    Severity,
    VectorExecutionResult,
)


def test_attack_vector_model():
    vec = AttackVector(
        id="SSRF-TEST-001",
        name="Test Vector",
        category=AttackCategory.SSRF,
        severity=Severity.HIGH,
        description="Test description",
        payload_command="curl http://169.254.169.254",
        indicator_pattern="ami-id",
    )
    assert vec.id == "SSRF-TEST-001"
    assert vec.category == AttackCategory.SSRF
    assert vec.severity == Severity.HIGH
    assert vec.safe_simulation is True


def test_layer_summary_cfr_calculation():
    summary = LayerSummary(
        layer=HarnessLayer.LAYER0_HOST,
        layer_name="Layer 0: Host",
        total_vectors=20,
        blocked_count=0,
        contained_count=2,
        failure_count=18,
        error_count=0,
        cfr_pct=90.0,
        csr_pct=10.0,
        avg_detection_ms=0.0,
        avg_execution_ms=12.5,
        baseline_latency_ms=15.0,
    )
    assert summary.cfr_pct == 90.0
    assert summary.csr_pct == 10.0
    assert summary.failure_count == 18
