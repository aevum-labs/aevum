# SPDX-License-Identifier: Apache-2.0
"""Witness — TOCTOU-protecting context snapshot for NAVIGATE → commit chains.

TOCTOU (Time-of-Check to Time-of-Use) is a race condition where the state verified at
check time differs from the state present at use time. In the agent context: a consent
grant checked at query() time may be revoked before the query result is used in commit()
or in a downstream agent call. Without protection, an agent could act on data it is no
longer consented to access.

The Witness seals a query result against the consent state at the moment of the query.
It captures two things: (1) the consent ledger's sequence watermark at query time, and
(2) a hash of the query results. At commit time, revalidate() checks that the watermark
has not advanced (no new revocations) and that the results are unchanged. If either check
fails, StaleContextError is raised and the operation is denied — the query must be
re-executed under the current consent state.

Spec reference: Phase 12a — Context Witness.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from typing import Any


@dataclasses.dataclass(frozen=True)
class Witness:
    """Immutable context snapshot captured at query() time and validated at commit() time.

    Fields:
        sequence_watermark: The consent ledger's max sequence number at capture time,
            for the queried subject_ids. If this advances before commit(), at least one
            new consent event (grant or revocation) has occurred — the context is stale.
        subject_ids:        The subjects whose consent state was checked at capture time.
            Sorted for stable comparison across capture and revalidate calls.
        result_digest:      SHA-256 of the canonical query results dict at capture time.
            If this changes between capture and revalidate, the underlying data changed —
            the agent would be acting on different data than was shown for review.
        captured_at_ns:     Nanosecond POSIX timestamp for forensic ordering of witnesses.
            Not used in revalidate() logic; recorded for audit purposes only.
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
    """Raised by revalidate() when the consent state changed between capture and validation.

    A StaleContextError means the agent has been operating with a snapshot of the consent
    ledger that is no longer current. The query result must be discarded, a fresh query
    must be executed under the current consent state, and a new Witness must be captured.
    Acting on a stale result could mean using data the subject has since revoked consent for.

    The engine converts this into an error OutputEnvelope rather than propagating the
    exception to application code. Attributes old_watermark and new_watermark are available
    for diagnostic logging.
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
    """Build a Witness from the current ledger state and query results at query() time.

    The watermark is the maximum consent-ledger sequence number for the queried subjects.
    Any advance in this sequence — a new grant or revocation — invalidates the snapshot.
    The result_digest is SHA-256 of the canonical (sort_keys) JSON of the results, so
    any change to the returned data (including re-ordering) invalidates the snapshot.

    Call this at the end of query() immediately before returning results, so that the
    snapshot faithfully represents the state under which the results were produced.

    Args:
        subject_ids: The subjects whose data was queried.
        results:     The query results dict to snapshot.
        ledger:      AuditLedgerProtocol — provides max_sequence_for_subjects().

    Returns:
        Witness: Immutable snapshot of ledger watermark and result digest.
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
    """Verify that the consent state and query results have not changed since capture.

    Two checks run independently so the caller can distinguish the failure mode:
      1. Sequence watermark: the consent ledger's max sequence for the witness subjects
         must still equal the captured watermark. An advance means a new grant or revocation
         has occurred — the consent state the agent was operating under has changed.
      2. Result digest: SHA-256 of the current results must match the captured digest.
         A mismatch means the underlying data changed (different graph state).

    Either failure raises StaleContextError, which the engine converts to an error
    OutputEnvelope. The agent must re-execute the query, capture a fresh Witness, and
    re-present the updated results for review before proceeding.

    Args:
        witness: The Witness captured at query() time.
        results: The results that are about to be acted upon (must match witness.result_digest).
        ledger:  AuditLedgerProtocol — provides max_sequence_for_subjects() for comparison.

    Raises:
        StaleContextError: If the watermark has advanced or the result digest differs.
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
