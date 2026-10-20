"""Base abstract harness for sandbox containment evaluation."""

from abc import ABC, abstractmethod
from pathlib import Path
from agent_sandbox_evals.models import AttackVector, HarnessLayer, VectorExecutionResult


class BaseHarness(ABC):
    """Abstract base class for sandbox evaluation harnesses."""

    def __init__(self, layer: HarnessLayer):
        self.layer = layer

    @property
    def name(self) -> str:
        return self.layer.display_name

    @abstractmethod
    async def execute(self, vector: AttackVector, workspace_dir: Path) -> VectorExecutionResult:
        """Executes an attack vector probe inside this isolation harness.

        Args:
            vector: The adversarial attack vector to probe.
            workspace_dir: Directory representing the agent's assigned workspace.

        Returns:
            VectorExecutionResult detailing containment status, duration, and output.
        """
        pass

    @abstractmethod
    async def benchmark_baseline(self, workspace_dir: Path) -> float:
        """Measures baseline execution latency (ms) for a benign command."""
        pass
