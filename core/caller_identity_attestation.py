from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import hashlib
import hmac
import json
import uuid


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso8601(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    value = value.astimezone(timezone.utc)

    return value.isoformat().replace(
        "+00:00",
        "Z",
    )


def _parse_iso8601(value: str) -> datetime:
    text = value.strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


@dataclass(frozen=True)
class CallerIdentityAttestation:
    attestation_id: str
    subject_agent_id: str
    issuer_id: str
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def identity_payload(self) -> dict:
        return {
            "subject_agent_id":
                self.subject_agent_id,
            "issuer_id":
                self.issuer_id,
            "issued_at":
                self.issued_at,
            "expires_at":
                self.expires_at,
            "nonce":
                self.nonce,
        }

    def unsigned_payload(self) -> dict:
        return {
            "attestation_id":
                self.attestation_id,
            **self.identity_payload(),
        }


@dataclass(frozen=True)
class CallerIdentityValidation:
    valid: bool
    reasons: Tuple[str, ...]
    authenticated_subject_agent_id: Optional[str]
    attestation_id: str
    issuer_id: str


class CallerIdentityAttestationIssuer:

    def __init__(
        self,
        *,
        issuer_id: str,
        signing_key: bytes,
    ):
        issuer_id = issuer_id.strip()

        if not issuer_id:
            raise ValueError(
                "issuer_id must not be empty"
            )

        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

        self._issuer_id = issuer_id
        self._signing_key = signing_key

    def _signature(
        self,
        payload: dict,
    ) -> str:
        return hmac.new(
            self._signing_key,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest().upper()

    def issue(
        self,
        *,
        subject_agent_id: str,
        ttl_seconds: int = 300,
        nonce: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> CallerIdentityAttestation:

        subject_agent_id = (
            subject_agent_id.strip()
        )

        if not subject_agent_id:
            raise ValueError(
                "subject_agent_id must not be empty"
            )

        if ttl_seconds <= 0:
            raise ValueError(
                "ttl_seconds must be greater than zero"
            )

        issued = now or _utc_now()

        if issued.tzinfo is None:
            issued = issued.replace(
                tzinfo=timezone.utc
            )

        issued = issued.astimezone(
            timezone.utc
        )

        expires = issued + timedelta(
            seconds=ttl_seconds
        )

        nonce_value = (
            nonce.strip()
            if nonce is not None
            else uuid.uuid4().hex
        )

        if not nonce_value:
            raise ValueError(
                "nonce must not be empty"
            )

        identity_payload = {
            "subject_agent_id":
                subject_agent_id,
            "issuer_id":
                self._issuer_id,
            "issued_at":
                _iso8601(issued),
            "expires_at":
                _iso8601(expires),
            "nonce":
                nonce_value,
        }

        attestation_id = hashlib.sha256(
            _canonical_json(
                identity_payload
            )
        ).hexdigest().upper()

        unsigned_payload = {
            "attestation_id":
                attestation_id,
            **identity_payload,
        }

        signature = self._signature(
            unsigned_payload
        )

        return CallerIdentityAttestation(
            attestation_id=
                attestation_id,
            subject_agent_id=
                subject_agent_id,
            issuer_id=
                self._issuer_id,
            issued_at=
                identity_payload[
                    "issued_at"
                ],
            expires_at=
                identity_payload[
                    "expires_at"
                ],
            nonce=
                nonce_value,
            signature=
                signature,
        )


class CallerIdentityAttestationVerifier:

    def __init__(
        self,
        *,
        issuer_id: str,
        signing_key: bytes,
    ):
        issuer_id = issuer_id.strip()

        if not issuer_id:
            raise ValueError(
                "issuer_id must not be empty"
            )

        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

        self._issuer_id = issuer_id
        self._signing_key = signing_key

    def _expected_signature(
        self,
        attestation:
            CallerIdentityAttestation,
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
        *,
        attestation:
            CallerIdentityAttestation,
        now: Optional[datetime] = None,
    ) -> CallerIdentityValidation:

        reasons = []

        subject_agent_id = (
            attestation.subject_agent_id
            .strip()
        )

        issuer_id = (
            attestation.issuer_id
            .strip()
        )

        nonce = (
            attestation.nonce
            .strip()
        )

        if not subject_agent_id:
            reasons.append(
                "CALLER_IDENTITY_SUBJECT_MISSING"
            )

        if not issuer_id:
            reasons.append(
                "CALLER_IDENTITY_ISSUER_MISSING"
            )

        elif issuer_id != self._issuer_id:
            reasons.append(
                "CALLER_IDENTITY_ISSUER_UNAUTHORIZED"
            )

        if not nonce:
            reasons.append(
                "CALLER_IDENTITY_NONCE_MISSING"
            )

        expected_identity_payload = {
            "subject_agent_id":
                attestation.subject_agent_id,
            "issuer_id":
                attestation.issuer_id,
            "issued_at":
                attestation.issued_at,
            "expires_at":
                attestation.expires_at,
            "nonce":
                attestation.nonce,
        }

        expected_attestation_id = (
            hashlib.sha256(
                _canonical_json(
                    expected_identity_payload
                )
            )
            .hexdigest()
            .upper()
        )

        if (
            attestation.attestation_id
            != expected_attestation_id
        ):
            reasons.append(
                "CALLER_IDENTITY_ATTESTATION_ID_MISMATCH"
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
                "CALLER_IDENTITY_SIGNATURE_INVALID"
            )

        try:
            issued_at = _parse_iso8601(
                attestation.issued_at
            )

            expires_at = _parse_iso8601(
                attestation.expires_at
            )

            current = now or _utc_now()

            if current.tzinfo is None:
                current = current.replace(
                    tzinfo=timezone.utc
                )

            current = current.astimezone(
                timezone.utc
            )

            if expires_at <= issued_at:
                reasons.append(
                    "CALLER_IDENTITY_TIME_RANGE_INVALID"
                )

            if current < issued_at:
                reasons.append(
                    "CALLER_IDENTITY_NOT_YET_VALID"
                )

            if current >= expires_at:
                reasons.append(
                    "CALLER_IDENTITY_ATTESTATION_EXPIRED"
                )

        except (
            TypeError,
            ValueError,
        ):
            reasons.append(
                "CALLER_IDENTITY_TIME_INVALID"
            )

        valid = not reasons

        return CallerIdentityValidation(
            valid=valid,
            reasons=tuple(reasons),
            authenticated_subject_agent_id=(
                subject_agent_id
                if valid
                else None
            ),
            attestation_id=
                attestation.attestation_id,
            issuer_id=
                attestation.issuer_id,
        )
