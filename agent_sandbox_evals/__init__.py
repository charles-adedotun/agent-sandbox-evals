"""agent-sandbox-evals: Empirical AI Agent Sandbox Containment Benchmark Suite."""

__version__ = "0.1.0"
__author__ = "Charles Adedotun <charles@krysp.org>"

from agent_sandbox_evals.models import (
    AttackCategory,
    AttackVector,
    BenchmarkReport,
    ContainmentOutcome,
    HarnessLayer,
    LayerSummary,
    Severity,
    VectorExecutionResult,
)
from agent_sandbox_evals.runner import BenchmarkRunner
from agent_sandbox_evals.vectors.matrix import ATTACK_VECTORS, get_all_vectors

__all__ = [
    "AttackCategory",
    "AttackVector",
    "BenchmarkReport",
    "ContainmentOutcome",
    "HarnessLayer",
    "LayerSummary",
    "Severity",
    "VectorExecutionResult",
    "BenchmarkRunner",
    "ATTACK_VECTORS",
    "get_all_vectors",
]
