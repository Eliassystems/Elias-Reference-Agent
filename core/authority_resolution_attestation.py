from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import hashlib
import hmac
import json

from core.authority_resolution import AuthorityResolution


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class AuthorityResolutionAttestation:
    resolver_id: str
    resolution_hash: str
    signature: str

    def unsigned_payload(self) -> dict:
        return {
            "resolver_id": self.resolver_id,
            "resolution_hash": self.resolution_hash,
        }


@dataclass(frozen=True)
class AttestedAuthorityResolution:
    resolution: AuthorityResolution
    attestation: AuthorityResolutionAttestation


@dataclass(frozen=True)
class AuthorityResolutionAttestationValidation:
    valid: bool
    reasons: Tuple[str, ...]


class AuthorityResolutionAttestationIssuer:

    def __init__(
        self,
        *,
        resolver_id: str,
        signing_key: bytes,
    ):
        resolver_id = resolver_id.strip()

        if not resolver_id:
            raise ValueError(
                "resolver_id must be established"
            )

        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

        self._resolver_id = resolver_id
        self._signing_key = signing_key

    def _signature(self, payload: dict) -> str:
        return hmac.new(
            self._signing_key,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest().upper()

    def issue(
        self,
        resolution: AuthorityResolution,
    ) -> AttestedAuthorityResolution:

        if not isinstance(
            resolution,
            AuthorityResolution,
        ):
            raise TypeError(
                "resolution must be AuthorityResolution"
            )

        unsigned = {
            "resolver_id":
                self._resolver_id,
            "resolution_hash":
                resolution.state_hash(),
        }

        attestation = AuthorityResolutionAttestation(
            resolver_id=
                self._resolver_id,
            resolution_hash=
                unsigned["resolution_hash"],
            signature=
                self._signature(unsigned),
        )

        return AttestedAuthorityResolution(
            resolution=resolution,
            attestation=attestation,
        )


class AuthorityResolutionAttestationVerifier:

    def __init__(
        self,
        *,
        resolver_id: str,
        signing_key: bytes,
    ):
        resolver_id = resolver_id.strip()

        if not resolver_id:
            raise ValueError(
                "resolver_id must be established"
            )

        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

        self._resolver_id = resolver_id
        self._signing_key = signing_key

    def _expected_signature(
        self,
        attestation: AuthorityResolutionAttestation,
    ) -> str:

        return hmac.new(
            self._signing_key,
            _canonical_json(
                attestation.unsigned_payload()
            ),
            hashlib.sha256,
        ).hexdigest().upper()

    def verify(
        self,
        evidence: AttestedAuthorityResolution,
    ) -> AuthorityResolutionAttestationValidation:

        reasons = []

        if not isinstance(
            evidence,
            AttestedAuthorityResolution,
        ):
            return AuthorityResolutionAttestationValidation(
                valid=False,
                reasons=(
                    "AUTHORITY_RESOLUTION_ATTESTATION_MISSING",
                ),
            )

        resolution = evidence.resolution
        attestation = evidence.attestation

        if not isinstance(
            resolution,
            AuthorityResolution,
        ):
            reasons.append(
                "AUTHORITY_RESOLUTION_INVALID"
            )

        if not isinstance(
            attestation,
            AuthorityResolutionAttestation,
        ):
            reasons.append(
                "AUTHORITY_RESOLUTION_ATTESTATION_INVALID"
            )

        if reasons:
            return AuthorityResolutionAttestationValidation(
                valid=False,
                reasons=tuple(reasons),
            )

        if (
            attestation.resolver_id
            != self._resolver_id
        ):
            reasons.append(
                "AUTHORITY_RESOLVER_ID_MISMATCH"
            )

        actual_resolution_hash = (
            resolution.state_hash()
        )

        if (
            attestation.resolution_hash
            != actual_resolution_hash
        ):
            reasons.append(
                "AUTHORITY_RESOLUTION_HASH_MISMATCH"
            )

        expected_signature = (
            self._expected_signature(
                attestation
            )
        )

        if not hmac.compare_digest(
            attestation.signature,
            expected_signature,
        ):
            reasons.append(
                "AUTHORITY_RESOLUTION_SIGNATURE_INVALID"
            )

        return AuthorityResolutionAttestationValidation(
            valid=not reasons,
            reasons=tuple(reasons),
        )
