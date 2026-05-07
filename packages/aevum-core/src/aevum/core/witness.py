from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from typing import Any


@dataclasses.dataclass(frozen=True)
class Witness:
    """
    Context snapshot captured at query() time.
    Validated at commit() to detect stale context.
    Spec: Phase 12a — Context Witness.
    """

    sequence_watermark: int
    subject_ids: tuple[str, ...]
    result_digest: str
    captured_at_ns: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence_watermark": self.sequence_watermark,
            "subject_ids": list(self.subject_ids),
            "result_digest": self.result_digest,
            "captured_at_ns": self.captured_at_ns,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Witness:
        return cls(
            sequence_watermark=int(d["sequence_watermark"]),
            subject_ids=tuple(d["subject_ids"]),
            result_digest=str(d["result_digest"]),
            captured_at_ns=int(d["captured_at_ns"]),
        )


class StaleContextError(Exception):
    """
    Raised internally when revalidate() detects staleness.
    The engine converts this to an error OutputEnvelope.
    """

    def __init__(
        self,
        reason: str,
        old_watermark: int,
        new_watermark: int,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.old_watermark = old_watermark
        self.new_watermark = new_watermark


def _digest_results(results: dict[str, Any]) -> str:
    """
    SHA-256 of the canonicalised query results dict.
    Sort keys at every level to guarantee stability.
    """
    blob = json.dumps(
        results,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return hashlib.sha256(blob).hexdigest()


def capture(
    subject_ids: list[str],
    results: dict[str, Any],
    ledger: Any,  # AuditLedgerProtocol
) -> Witness:
    """
    Build a Witness from the current ledger state and query results.
    Call this at the end of query() before returning.
    """
    watermark = ledger.max_sequence_for_subjects(subject_ids)
    return Witness(
        sequence_watermark=watermark,
        subject_ids=tuple(sorted(subject_ids)),
        result_digest=_digest_results(results),
        captured_at_ns=time.time_ns(),
    )


def revalidate(
    witness: Witness,
    results: dict[str, Any],
    ledger: Any,  # AuditLedgerProtocol
) -> None:
    """
    Verify context has not changed since witness was captured.
    Raises StaleContextError if either check fails.
    Call this at the start of commit() when a witness is provided.
    Two checks run independently so the caller knows which failed:
      1. Sequence watermark: any new ingest for these subjects?
      2. Result digest: does re-executing the query give the same data?
    """
    current = ledger.max_sequence_for_subjects(list(witness.subject_ids))
    if current != witness.sequence_watermark:
        raise StaleContextError(
            f"New ingest events detected for subjects "
            f"{witness.subject_ids!r}: watermark "
            f"{witness.sequence_watermark} -> {current}",
            old_watermark=witness.sequence_watermark,
            new_watermark=current,
        )
    current_digest = _digest_results(results)
    if current_digest != witness.result_digest:
        raise StaleContextError(
            "Query results changed since witness was captured",
            old_watermark=witness.sequence_watermark,
            new_watermark=current,
        )
