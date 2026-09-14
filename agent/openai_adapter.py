from __future__ import annotations

import os
from typing import Optional

from agent.intent import CanonicalIntent
from agent.model_adapter import (
    ModelAdapter,
    ModelOutput,
)


class OpenAIModelAdapter(ModelAdapter):
    """
    Real OpenAI intelligence adapter for Elias.

    Important boundary:
    - The model receives constituted intent.
    - The model does NOT receive the execution permit signer.
    - The model does NOT receive the consequence tool.
    - The model does NOT grant itself authority.
    - Model output remains a proposal until Elias binds
      and governs the exact consequence.
    """

    def __init__(
        self,
        *,
        model: Optional[str] = None,
    ):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError(
                "OPENAI_PACKAGE_NOT_INSTALLED"
            ) from exc

        api_key = os.environ.get(
            "OPENAI_API_KEY"
        )

        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY_NOT_SET"
            )

        self.model = (
            model
            or os.environ.get("ELIAS_MODEL")
            or "gpt-5.6"
        )

        self._client = OpenAI(
            api_key=api_key
        )

        self.calls = 0

    def generate(
        self,
        intent: CanonicalIntent,
    ) -> ModelOutput:

        self.calls += 1

        instructions = """
You are the intelligence component inside the
Elias Reference Agent.

You are NOT the authority source.

You may reason, draft, analyse, and propose.

You may not:
- claim that you possess execution authority,
- redefine the constituted target,
- expand the permitted consequence,
- treat capability as authority,
- alter the constitutional boundary,
- claim that your own output authorises execution.

Return only the content requested by the
constituted objective.

Elias governance outside the model will decide
whether any resulting consequence is permitted.
""".strip()

        user_input = f"""
CONSTITUTED OBJECTIVE:
{intent.objective}

ACTOR:
{intent.actor_id}

GOVERNED TARGET:
{intent.target}

REQUESTED PERMISSION:
{intent.permission}

TOOL:
{intent.tool}

CONSEQUENCE CLASS:
{intent.consequence_class}

POLICY VERSION:
{intent.policy_version}

CONSTRAINTS:
{list(intent.constraints)}
""".strip()

        response = self._client.responses.create(
            model=self.model,
            instructions=instructions,
            input=user_input,
        )

        output_text = (
            response.output_text or ""
        ).strip()

        if not output_text:
            raise RuntimeError(
                "MODEL_RETURNED_EMPTY_OUTPUT"
            )

        return ModelOutput(
            content=output_text,
            model_id=self.model,
            metadata={
                "provider": "OPENAI",
                "response_id":
                    getattr(
                        response,
                        "id",
                        None,
                    ),
                "call_number":
                    self.calls,
            },
        )
