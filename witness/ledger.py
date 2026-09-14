from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple, Union
import hashlib
import json
import os
import uuid


GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class WitnessLedger:
    """
    Elias witness ledger.

    Runtime writes are append-only and hash chained.

    NOTE:
    This is tamper-evident inside the current reference runtime.
    It is not yet an externally anchored immutable ledger.
    """

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._lock = RLock()

    def _records_unlocked(self) -> List[dict]:
        records = []

        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, start=1):
                raw = raw.strip()

                if not raw:
                    continue

                try:
                    records.append(json.loads(raw))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        "WITNESS_LEDGER_PARSE_ERROR line={}".format(
                            line_number
                        )
                    ) from exc

        return records

    def records(self) -> List[dict]:
        with self._lock:
            return self._records_unlocked()

    def _head_hash_unlocked(self) -> str:
        records = self._records_unlocked()

        if not records:
            return GENESIS_HASH

        return records[-1]["receipt_hash"]

    def append(
        self,
        *,
        event_type: str,
        constitution_version: str,
        actor_identity: str,
        authority_source: str,
        authority_epoch: int,
        intent_hash: str,
        target: str,
        tool: str,
        consequence_class: str,
        governance_verdict: str,
        verdict_reason: str,
        execution_result: str,
        permit_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> dict:

        with self._lock:
            previous_hash = self._head_hash_unlocked()

            unsigned = {
                "event_id": str(uuid.uuid4()).upper(),
                "timestamp": _utc_now_iso(),
                "event_type": event_type,
                "constitution_version": constitution_version,
                "actor_identity": actor_identity,
                "authority_source": authority_source,
                "authority_epoch": authority_epoch,
                "intent_hash": intent_hash,
                "target": target,
                "tool": tool,
                "consequence_class": consequence_class,
                "governance_verdict": governance_verdict,
                "verdict_reason": verdict_reason,
                "execution_result": execution_result,
                "permit_id": permit_id,
                "details": details or {},
                "previous_receipt_hash": previous_hash,
            }

            receipt_hash = hashlib.sha256(
                _canonical_json(unsigned)
            ).hexdigest().upper()

            record = dict(unsigned)
            record["receipt_hash"] = receipt_hash

            serialized = json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )

            with self.path.open(
                "a",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                handle.write(serialized + "\n")
                handle.flush()
                os.fsync(handle.fileno())

            return record

    def has_consumed_permit(self, permit_id: str) -> bool:
        """
        A durable PRE_EXECUTION_AUTHORIZED witness consumes the permit.

        If the runtime crashes after this point, the historical permit
        must not silently become executable again on restart.
        """

        with self._lock:
            records = self._records_unlocked()

        for record in records:
            if (
                record.get("permit_id") == permit_id
                and record.get("event_type")
                == "PRE_EXECUTION_AUTHORIZED"
            ):
                return True

        return False

    def verify_chain(self) -> Tuple[bool, Tuple[str, ...]]:
        errors = []

        with self._lock:
            records = self._records_unlocked()

        expected_previous = GENESIS_HASH

        for index, record in enumerate(records, start=1):

            actual_previous = record.get(
                "previous_receipt_hash"
            )

            if actual_previous != expected_previous:
                errors.append(
                    "CHAIN_PREVIOUS_HASH_MISMATCH_AT_RECORD_{}".format(
                        index
                    )
                )

            stored_hash = record.get("receipt_hash")

            if not stored_hash:
                errors.append(
                    "MISSING_RECEIPT_HASH_AT_RECORD_{}".format(
                        index
                    )
                )
                expected_previous = ""
                continue

            unsigned = dict(record)
            unsigned.pop("receipt_hash", None)

            computed_hash = hashlib.sha256(
                _canonical_json(unsigned)
            ).hexdigest().upper()

            if stored_hash != computed_hash:
                errors.append(
                    "RECEIPT_HASH_MISMATCH_AT_RECORD_{}".format(
                        index
                    )
                )

            expected_previous = stored_hash

        return len(errors) == 0, tuple(errors)
