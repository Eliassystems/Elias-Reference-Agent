from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple
import hashlib
import json

from core.authority import AuthorityState


class AuthorityResolutionStatus(str, Enum):
    ESTABLISHED = "ESTABLISHED"
    CONFLICT = "CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class AuthorityResolution:
    """
    Governed result of present-tense authority resolution.

    Distinguishes:
    - one established current authority state,
    - conflicting authentic observations,
    - unavailable authority information,
    - indeterminate current standing.

    Only ESTABLISHED may carry executable authority.
    """

    status: AuthorityResolutionStatus
    authority: Optional[AuthorityState]
    observations: Tuple[AuthorityState, ...]
    reason: str

    def __post_init__(self):

        if not isinstance(
            self.status,
            AuthorityResolutionStatus,
        ):
            raise TypeError(
                "status must be AuthorityResolutionStatus"
            )

        if not self.reason.strip():
            raise ValueError(
                "authority resolution reason must be established"
            )

        for observation in self.observations:
            if not isinstance(
                observation,
                AuthorityState,
            ):
                raise TypeError(
                    "all observations must be AuthorityState"
                )

        if (
            self.status
            == AuthorityResolutionStatus.ESTABLISHED
        ):
            if not isinstance(
                self.authority,
                AuthorityState,
            ):
                raise ValueError(
                    "ESTABLISHED resolution requires AuthorityState"
                )

            if len(self.observations) < 1:
                raise ValueError(
                    "ESTABLISHED resolution requires at least one observation"
                )

            for observation in self.observations:
                if observation != self.authority:
                    raise ValueError(
                        "ESTABLISHED resolution observations must "
                        "match executable authority"
                    )

        else:
            if self.authority is not None:
                raise ValueError(
                    "non-ESTABLISHED resolution cannot carry executable authority"
                )

        if (
            self.status
            == AuthorityResolutionStatus.CONFLICT
            and len(self.observations) < 2
        ):
            raise ValueError(
                "CONFLICT resolution requires at least two observations"
            )

        if (
            self.status
            == AuthorityResolutionStatus.CONFLICT
            and all(
                observation == self.observations[0]
                for observation in self.observations[1:]
            )
        ):
            raise ValueError(
                "CONFLICT resolution requires materially different observations"
            )

    @classmethod
    def established(
        cls,
        authority: AuthorityState,
        reason: str = "CURRENT_AUTHORITY_ESTABLISHED",
    ) -> "AuthorityResolution":

        return cls(
            status=AuthorityResolutionStatus.ESTABLISHED,
            authority=authority,
            observations=(authority,),
            reason=reason,
        )

    @classmethod
    def conflict(
        cls,
        observations,
        reason: str = "AUTHORITY_OBSERVATIONS_CONFLICT",
    ) -> "AuthorityResolution":

        observations = tuple(observations)

        return cls(
            status=AuthorityResolutionStatus.CONFLICT,
            authority=None,
            observations=observations,
            reason=reason,
        )

    @classmethod
    def unavailable(
        cls,
        observations=(),
        reason: str = "AUTHORITY_INFORMATION_UNAVAILABLE",
    ) -> "AuthorityResolution":

        return cls(
            status=AuthorityResolutionStatus.UNAVAILABLE,
            authority=None,
            observations=tuple(observations),
            reason=reason,
        )

    @classmethod
    def indeterminate(
        cls,
        observations=(),
        reason: str = "CURRENT_AUTHORITY_INDETERMINATE",
    ) -> "AuthorityResolution":

        return cls(
            status=AuthorityResolutionStatus.INDETERMINATE,
            authority=None,
            observations=tuple(observations),
            reason=reason,
        )

    def canonical_payload(self) -> dict:

        return {
            "status": self.status.value,
            "reason": self.reason,
            "authority": (
                self.authority.canonical_payload()
                if self.authority is not None
                else None
            ),
            "observations": [
                observation.canonical_payload()
                for observation in self.observations
            ],
        }

    def state_hash(self) -> str:

        payload = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(
            payload
        ).hexdigest().upper()
