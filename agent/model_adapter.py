from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from agent.intent import CanonicalIntent


@dataclass(frozen=True)
class ModelOutput:
    content: str
    model_id: str
    metadata: Dict[str, Any]


class ModelAdapter:
    """
    Intelligence interface.

    Elias governance must not depend upon
    one specific model provider.
    """

    def generate(
        self,
        intent: CanonicalIntent,
    ) -> ModelOutput:
        raise NotImplementedError


class DeterministicDemoModel(ModelAdapter):
    """
    Initial reference intelligence.

    No external API.

    This exists so the governance architecture can
    be tested before any frontier model is attached.
    """

    def __init__(self):
        self.calls = 0

    def generate(
        self,
        intent: CanonicalIntent,
    ) -> ModelOutput:

        self.calls += 1

        content = (
            "ELIAS DEMO OUTPUT | "
            "Objective: {} | "
            "Governed target: {}"
        ).format(
            intent.objective,
            intent.target,
        )

        return ModelOutput(
            content=content,
            model_id=
                "ELIAS-DETERMINISTIC-DEMO-001",
            metadata={
                "call_number": self.calls,
                "provider":
                    "LOCAL_REFERENCE",
            },
        )
