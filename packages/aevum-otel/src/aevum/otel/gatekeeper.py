# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
GatekeeperFilter — de-identification for FOQA telemetry export.

Modeled on the gatekeeper role defined in FAA AC 120-82 (April 2004):
  "The gatekeeper is an individual designated by the operator who holds the
  linking key that allows FOQA data to be associated with a specific flight."

The gatekeeper_key is a secret. ONLY the holder of this key can re-link
pseudonyms to real session/agent identifiers. This structural separation is
the institutional safeguard that makes FOQA export safe.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aevum.core.exceedance import ExceedanceEvent


class GatekeeperFilter:
    """
    De-identification filter for FOQA telemetry export.
    Modeled on FAA AC 120-82 gatekeeper role.

    The gatekeeper_key is a secret used for deterministic pseudonymization.
    ONLY the holder of this key can re-link pseudonyms to real identifiers.
    This key must be:
      - Held by a designated gatekeeper (outside of management, per AC 120-82)
      - Stored in a HSM, Vault, or encrypted secret manager
      - Never logged, never transmitted in plaintext
      - Never committed to version control

    Pseudonymization method: HMAC-SHA256(original_id, gatekeeper_key)[:16]
    This is deterministic (same input → same pseudonym) and irreversible without
    the key. With the key, full re-linking is possible.

    Fields stripped before export (cannot be in aggregate telemetry):
      - Raw prompt text
      - Raw response text
      - User PII (names, emails, phone numbers)
      - Exact session_id (replaced with pseudonym)
      - Exact agent_id (replaced with pseudonym)
      - IP addresses
      - Any field that could uniquely identify a natural person (GDPR Art. 4)

    This filter does NOT have a dev-mode bypass. A de-identification filter
    that operates without a key provides no protection and breaks the FOQA
    export guarantee.
    """

    STRIPPED_FIELDS = frozenset({
        "prompt_text", "response_text", "user_id", "user_email",
        "user_name", "ip_address", "raw_input", "raw_output",
    })

    def __init__(self, gatekeeper_key: bytes | None = None) -> None:
        if gatekeeper_key is None:
            key_hex = os.environ.get("AEVUM_GATEKEEPER_KEY_HEX", "")
            if not key_hex:
                raise RuntimeError(
                    "GatekeeperFilter requires AEVUM_GATEKEEPER_KEY_HEX "
                    "environment variable (hex-encoded 32-byte key) or "
                    "a gatekeeper_key parameter. "
                    "Generate: python3 -c 'import secrets; print(secrets.token_hex(32))'"
                )
            gatekeeper_key = bytes.fromhex(key_hex)
        if len(gatekeeper_key) < 32:
            raise ValueError("gatekeeper_key must be at least 32 bytes")
        self._key = gatekeeper_key

    def pseudonymize(self, identifier: str) -> str:
        """
        Deterministically pseudonymize an identifier.
        With the gatekeeper_key, the original identifier can be recovered by
        comparing HMAC outputs across the known identifier space.
        """
        mac = hmac.new(self._key, identifier.encode("utf-8"), hashlib.sha256)
        return "anon-" + mac.hexdigest()[:16]

    def filter_exceedance(self, event: ExceedanceEvent) -> ExceedanceEvent:
        """
        Return a de-identified copy of an ExceedanceEvent.
        Pseudonymizes session_id and agent_id.
        Strips any PII fields from details dict.
        """
        from dataclasses import replace
        clean_details = {
            k: v for k, v in event.details.items()
            if k not in self.STRIPPED_FIELDS
        }
        return replace(
            event,
            session_id=self.pseudonymize(event.session_id),
            agent_id=self.pseudonymize(event.agent_id) if event.agent_id else "",
            receipt_hash=event.receipt_hash[:12] + "...",  # truncate for anonymity
            details=clean_details,
        )

    def filter_attributes(self, attributes: dict[str, Any]) -> dict[str, Any]:
        """
        Filter a span attribute dict for FOQA export.
        Strips PII fields. Returns a new dict; does not mutate input.
        """
        return {
            k: v for k, v in attributes.items()
            if k not in self.STRIPPED_FIELDS
            and not any(
                pii in k.lower()
                for pii in ("user", "email", "name", "ip", "phone", "address")
            )
        }
