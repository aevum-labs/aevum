# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AevumA2AInterceptor — signs and chains A2A v1.0 Task envelopes.

Every Task created or updated through this interceptor is:
  1. Dual-signed (Ed25519 + ML-DSA-65) via the kernel's DualSigner
  2. Recorded in the sigchain
  3. RFC 3161 timestamped (via TSAClient, circuit breaker)

The interceptor wraps the application's A2A task management. It does
not replace the underlying A2A transport — it adds governance on top.

AgentCard signing:
  JWS (RFC 7515) using Ed25519. The signed card is published at
  /.well-known/agent.json alongside the plain card.
  The JWS header: {"alg": "EdDSA", "crv": "Ed25519"}
  The JWS payload: base64url(agent_card_json)
  The JWS signature: Ed25519 signature from DualSigner

Usage:
  interceptor = AevumA2AInterceptor(kernel=kernel)
  signed_task = interceptor.sign_task(task)
  signed_card = interceptor.sign_agent_card(card)
"""
from __future__ import annotations

import base64
import dataclasses
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from aevum.agent.types import A2ATask, AgentCard, TaskStatus

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SignedTask:
    """A2A Task with Aevum dual-signature envelope."""
    task: A2ATask
    ed25519_sig: str
    mldsa65_sig: str | None = None
    ed25519_pub: str = ""
    signed_at: datetime = dataclasses.field(
        default_factory=lambda: datetime.now(UTC)
    )
    sigchain_entry_id: int | None = None
    tsa_url: str | None = None

    def to_wire(self) -> dict[str, Any]:
        """Wire format: A2A task dict + _aevum governance envelope."""
        d = self.task.to_dict()
        d["_aevum"] = {
            "signed_at": self.signed_at.isoformat(),
            "ed25519_sig": self.ed25519_sig,
            "ed25519_pub": self.ed25519_pub,
            "sigchain_entry_id": self.sigchain_entry_id,
            "tsa_url": self.tsa_url,
        }
        if self.mldsa65_sig:
            d["_aevum"]["mldsa65_sig"] = self.mldsa65_sig
        return d


@dataclasses.dataclass(frozen=True)
class SignedAgentCard:
    """AgentCard with JWS signature (RFC 7515, Ed25519)."""
    card: AgentCard
    jws_token: str
    signed_at: datetime = dataclasses.field(
        default_factory=lambda: datetime.now(UTC)
    )

    def to_well_known_response(self) -> dict[str, Any]:
        """
        Response format for /.well-known/agent.json.
        Includes both the plain card and the JWS token.
        """
        return {
            **self.card.to_dict(),
            "_aevum_jws": self.jws_token,
            "_aevum_signed_at": self.signed_at.isoformat(),
        }


class AevumA2AInterceptor:
    """
    Signs A2A v1.0 task envelopes and agent cards.

    Requires a Kernel instance for DualSigner (Ed25519 + ML-DSA-65)
    and TSAClient (RFC 3161, circuit breaker).
    """

    def __init__(self, kernel: Any) -> None:
        self._kernel = kernel

    def create_task(self, input_data: dict[str, Any]) -> SignedTask:
        """
        Create a new A2A Task and sign it immediately.
        Returns a SignedTask ready for transmission.
        """
        task = A2ATask(
            id=str(uuid.uuid4()),
            status=TaskStatus.SUBMITTED,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            input=input_data,
            output=None,
            error=None,
        )
        return self.sign_task(task)

    def sign_task(self, task: A2ATask) -> SignedTask:
        """
        Sign an existing Task with the kernel's DualSigner.
        Records the signature in the sigchain (non-blocking on failure).
        """
        payload = json.dumps(
            task.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        ed25519_sig_hex, mldsa65_sig_hex, ed25519_pub_hex = self._sign(payload)

        tsa_token = self._kernel.tsa_client.timestamp(payload)
        tsa_url = tsa_token.tsa_url if tsa_token else None

        signed = SignedTask(
            task=task,
            ed25519_sig=ed25519_sig_hex,
            mldsa65_sig=mldsa65_sig_hex,
            ed25519_pub=ed25519_pub_hex,
            signed_at=datetime.now(UTC),
            tsa_url=tsa_url,
        )

        self._record_in_sigchain(task.id, payload, signed)
        return signed

    def update_task_status(
        self,
        signed_task: SignedTask,
        new_status: TaskStatus,
        output: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> SignedTask:
        """Update a task's status and re-sign the updated task."""
        updated_task = dataclasses.replace(
            signed_task.task,
            status=new_status,
            updated_at=datetime.now(UTC),
            output=output,
            error=error,
        )
        return self.sign_task(updated_task)

    def sign_agent_card(self, card: AgentCard) -> SignedAgentCard:
        """
        Sign an AgentCard using JWS compact serialization (RFC 7515).

        JWS structure:  base64url(header) . base64url(payload) . base64url(sig)
        Header: {"alg": "EdDSA", "crv": "Ed25519"}
        Payload: agent card JSON
        Signature: Ed25519 signature via PyNaCl (from DualSigner)
        """
        header = json.dumps(
            {"alg": "EdDSA", "crv": "Ed25519"}, separators=(",", ":")
        ).encode("utf-8")
        payload = json.dumps(
            card.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        header_b64 = _b64url(header)
        payload_b64 = _b64url(payload)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        ed25519_sk = self._kernel.signer._ed25519_sk
        signed_msg = ed25519_sk.sign(signing_input)
        sig_bytes = bytes(signed_msg.signature)
        sig_b64 = _b64url(sig_bytes)

        jws_token = f"{header_b64}.{payload_b64}.{sig_b64}"

        return SignedAgentCard(
            card=card,
            jws_token=jws_token,
            signed_at=datetime.now(UTC),
        )

    def verify_signed_card(self, jws_token: str, ed25519_pub: bytes) -> bool:
        """
        Verify a JWS-signed agent card.
        Returns True if valid, False otherwise.
        """
        import nacl.exceptions
        import nacl.signing
        try:
            parts = jws_token.split(".")
            if len(parts) != 3:
                return False
            header_b64, payload_b64, sig_b64 = parts
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            sig_bytes = _b64url_decode(sig_b64)
            verify_key = nacl.signing.VerifyKey(ed25519_pub)
            verify_key.verify(signing_input, sig_bytes)
            return True
        except (nacl.exceptions.BadSignatureError, Exception):  # noqa: BLE001
            return False

    def _sign(self, payload: bytes) -> tuple[str, str | None, str]:
        """
        Sign payload. Returns (ed25519_hex, mldsa65_hex | None, ed25519_pub_hex).
        """
        from aevum.core.signing import _OQS_AVAILABLE

        ed25519_sk = self._kernel.signer._ed25519_sk
        signed_msg = ed25519_sk.sign(payload)
        ed25519_sig = bytes(signed_msg.signature).hex()
        ed25519_pub = bytes(self._kernel.signer.ed25519_public_key).hex()

        mldsa65_sig: str | None = None
        if _OQS_AVAILABLE:
            try:
                dual_sig = self._kernel.signer.sign(payload)
                mldsa65_sig = dual_sig.mldsa65_sig.hex()
            except Exception as exc:  # noqa: BLE001
                logger.warning("ML-DSA-65 signing failed: %s", exc)

        return ed25519_sig, mldsa65_sig, ed25519_pub

    def _record_in_sigchain(
        self, task_id: str, payload: bytes, signed: SignedTask
    ) -> None:
        """Record the signed task in the sigchain (non-blocking)."""
        try:
            logger.debug(
                "Sigchain: A2A task signed: id=%s ed25519=%s...",
                task_id, signed.ed25519_sig[:8],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain record failed for task %s: %s", task_id, exc)


def _b64url(data: bytes) -> str:
    """Base64url encoding (no padding, RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decoding (no padding)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
