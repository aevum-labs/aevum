# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Phase 6 test suite for aevum-agent:
  - A2A v1.0 types (TaskStatus, AgentCapability, A2ATask, AgentCard)
  - AevumA2AInterceptor (sign_task, sign_agent_card, verify_signed_card)
  - JWS compact serialization (RFC 7515)
  - Base64url helpers

NO tests/__init__.py (standing rule Rule 01).
"""
from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from enum import StrEnum
from unittest.mock import MagicMock

import pytest

from aevum.agent.interceptor import (
    AevumA2AInterceptor,
    SignedAgentCard,
    SignedTask,
    _b64url,
    _b64url_decode,
)
from aevum.agent.types import A2ATask, AgentCapability, AgentCard, TaskStatus


def _make_kernel() -> MagicMock:
    """Create a mock kernel with a real Ed25519 signing key."""
    import nacl.signing
    ed25519_sk = nacl.signing.SigningKey.generate()
    kernel = MagicMock()
    kernel.signer._ed25519_sk = ed25519_sk
    kernel.signer.ed25519_public_key = bytes(ed25519_sk.verify_key)
    kernel.tsa_client.timestamp.return_value = None
    return kernel


def _make_task() -> A2ATask:
    now = datetime.now(UTC)
    return A2ATask(
        id="task-1",
        status=TaskStatus.SUBMITTED,
        created_at=now,
        updated_at=now,
        input={"query": "test"},
        output=None,
        error=None,
    )


def _make_card() -> AgentCard:
    return AgentCard(
        name="TestAgent",
        description="A test agent",
        version="1.0.0",
        url="http://localhost:8080",
        capabilities=(AgentCapability.STREAMING,),
        skills=("summarize", "translate"),
    )


class TestTaskStatus:
    def test_is_strenum(self) -> None:
        assert issubclass(TaskStatus, StrEnum)

    def test_screaming_snake_case_submitted(self) -> None:
        assert TaskStatus.SUBMITTED == "SUBMITTED"

    def test_screaming_snake_case_running(self) -> None:
        assert TaskStatus.RUNNING == "RUNNING"

    def test_screaming_snake_case_completed(self) -> None:
        assert TaskStatus.COMPLETED == "COMPLETED"

    def test_screaming_snake_case_failed(self) -> None:
        assert TaskStatus.FAILED == "FAILED"

    def test_screaming_snake_case_cancelled(self) -> None:
        assert TaskStatus.CANCELLED == "CANCELLED"

    def test_five_statuses(self) -> None:
        assert len(TaskStatus) == 5

    def test_not_lowercase(self) -> None:
        for status in TaskStatus:
            assert status.value == status.value.upper(), f"{status.value} is not SCREAMING_SNAKE_CASE"

    def test_string_equality(self) -> None:
        assert str(TaskStatus.SUBMITTED) == "SUBMITTED"


class TestAgentCapability:
    def test_is_strenum(self) -> None:
        assert issubclass(AgentCapability, StrEnum)

    def test_streaming(self) -> None:
        assert AgentCapability.STREAMING == "STREAMING"

    def test_push_notifications(self) -> None:
        assert AgentCapability.PUSH_NOTIFICATIONS == "PUSH_NOTIFICATIONS"

    def test_state_transition_history(self) -> None:
        assert AgentCapability.STATE_TRANSITION_HISTORY == "STATE_TRANSITION_HISTORY"

    def test_three_capabilities(self) -> None:
        assert len(AgentCapability) == 3


class TestA2ATask:
    def test_frozen(self) -> None:
        task = _make_task()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            task.status = TaskStatus.RUNNING  # type: ignore[misc]

    def test_to_dict_no_kind_field(self) -> None:
        task = _make_task()
        d = task.to_dict()
        assert "kind" not in d

    def test_to_dict_has_required_fields(self) -> None:
        task = _make_task()
        d = task.to_dict()
        for key in ("id", "status", "created_at", "updated_at", "input"):
            assert key in d

    def test_to_dict_status_is_screaming_snake(self) -> None:
        task = _make_task()
        d = task.to_dict()
        assert d["status"] == "SUBMITTED"

    def test_output_absent_when_none(self) -> None:
        task = _make_task()
        d = task.to_dict()
        assert "output" not in d

    def test_error_absent_when_none(self) -> None:
        task = _make_task()
        d = task.to_dict()
        assert "error" not in d

    def test_output_present_when_set(self) -> None:
        task = dataclasses.replace(_make_task(), output={"result": "ok"})
        d = task.to_dict()
        assert "output" in d
        assert d["output"] == {"result": "ok"}

    def test_error_present_when_set(self) -> None:
        task = dataclasses.replace(_make_task(), error="something failed")
        d = task.to_dict()
        assert "error" in d
        assert d["error"] == "something failed"

    def test_metadata_absent_when_empty(self) -> None:
        task = _make_task()
        d = task.to_dict()
        assert "metadata" not in d

    def test_metadata_present_when_set(self) -> None:
        task = dataclasses.replace(_make_task(), metadata={"foo": "bar"})
        d = task.to_dict()
        assert "metadata" in d

    def test_to_dict_is_json_serializable(self) -> None:
        task = _make_task()
        json.dumps(task.to_dict())

    def test_created_at_is_iso_format(self) -> None:
        task = _make_task()
        d = task.to_dict()
        # Should parse as ISO 8601
        datetime.fromisoformat(d["created_at"])


class TestAgentCard:
    def test_frozen(self) -> None:
        card = _make_card()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            card.name = "other"  # type: ignore[misc]

    def test_to_dict_no_kind_field(self) -> None:
        card = _make_card()
        d = card.to_dict()
        assert "kind" not in d

    def test_to_dict_has_required_fields(self) -> None:
        card = _make_card()
        d = card.to_dict()
        for key in ("name", "description", "version", "url", "capabilities", "skills"):
            assert key in d

    def test_capabilities_are_strings(self) -> None:
        card = _make_card()
        d = card.to_dict()
        assert all(isinstance(c, str) for c in d["capabilities"])

    def test_capabilities_are_screaming_snake(self) -> None:
        card = _make_card()
        d = card.to_dict()
        for cap in d["capabilities"]:
            assert cap == cap.upper()

    def test_skills_are_list_of_strings(self) -> None:
        card = _make_card()
        d = card.to_dict()
        assert isinstance(d["skills"], list)
        assert all(isinstance(s, str) for s in d["skills"])

    def test_to_dict_is_json_serializable(self) -> None:
        card = _make_card()
        json.dumps(card.to_dict())

    def test_empty_capabilities_allowed(self) -> None:
        card = AgentCard(
            name="Min", description="", version="0.1", url="http://x",
            capabilities=(), skills=(),
        )
        d = card.to_dict()
        assert d["capabilities"] == []


class TestAevumA2AInterceptor:
    def test_create_task_returns_signed_task(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({"query": "hello"})
        assert isinstance(signed, SignedTask)

    def test_signed_task_has_ed25519_sig(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({"input": "test"})
        assert len(signed.ed25519_sig) == 128

    def test_signed_task_ed25519_sig_is_hex(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        int(signed.ed25519_sig, 16)

    def test_signed_task_status_is_submitted(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        assert signed.task.status == TaskStatus.SUBMITTED

    def test_to_wire_no_kind_field(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({"q": "test"})
        wire = signed.to_wire()
        assert "kind" not in wire

    def test_to_wire_has_aevum_envelope(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        wire = signed.to_wire()
        assert "_aevum" in wire
        assert "ed25519_sig" in wire["_aevum"]
        assert "signed_at" in wire["_aevum"]

    def test_to_wire_is_json_serializable(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({"q": "test"})
        json.dumps(signed.to_wire())

    def test_to_wire_has_task_fields(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({"data": 1})
        wire = signed.to_wire()
        assert "id" in wire
        assert "status" in wire
        assert "input" in wire

    def test_update_task_status_to_running(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        updated = interceptor.update_task_status(signed, TaskStatus.RUNNING)
        assert updated.task.status == TaskStatus.RUNNING

    def test_update_task_completed_with_output(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        done = interceptor.update_task_status(
            signed, TaskStatus.COMPLETED, output={"result": "ok"}
        )
        assert done.task.status == TaskStatus.COMPLETED
        assert done.task.output == {"result": "ok"}

    def test_update_task_failed_with_error(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        failed = interceptor.update_task_status(
            signed, TaskStatus.FAILED, error="timeout"
        )
        assert failed.task.status == TaskStatus.FAILED
        assert failed.task.error == "timeout"

    def test_update_task_is_re_signed(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        updated = interceptor.update_task_status(signed, TaskStatus.RUNNING)
        # Each sign produces a new signature over new payload
        assert isinstance(updated.ed25519_sig, str)
        assert len(updated.ed25519_sig) == 128

    def test_mldsa65_sig_none_without_oqs(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        from aevum.core.signing import _OQS_AVAILABLE
        if not _OQS_AVAILABLE:
            assert signed.mldsa65_sig is None

    def test_signed_at_is_recent(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        now = datetime.now(UTC)
        diff = abs((now - signed.signed_at).total_seconds())
        assert diff < 5

    def test_tsa_url_is_none_when_circuit_breaker_returns_none(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.create_task({})
        assert signed.tsa_url is None


class TestSignedAgentCard:
    def test_sign_returns_signed_card(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        assert isinstance(signed, SignedAgentCard)

    def test_jws_token_is_three_parts(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        parts = signed.jws_token.split(".")
        assert len(parts) == 3

    def test_jws_header_is_correct(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        header_b64 = signed.jws_token.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        assert header["alg"] == "EdDSA"
        assert header["crv"] == "Ed25519"

    def test_jws_payload_contains_card_fields(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        payload_b64 = signed.jws_token.split(".")[1]
        payload = json.loads(_b64url_decode(payload_b64))
        assert payload["name"] == "TestAgent"

    def test_verify_signed_card_valid(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        ed25519_pub = bytes(kernel.signer._ed25519_sk.verify_key)
        assert interceptor.verify_signed_card(signed.jws_token, ed25519_pub)

    def test_verify_tampered_payload_fails(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        parts = signed.jws_token.split(".")
        tampered_token = parts[0] + "." + _b64url(b'{"tampered":true}') + "." + parts[2]
        ed25519_pub = bytes(kernel.signer._ed25519_sk.verify_key)
        assert not interceptor.verify_signed_card(tampered_token, ed25519_pub)

    def test_verify_wrong_key_fails(self) -> None:
        import nacl.signing
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        wrong_key = bytes(nacl.signing.SigningKey.generate().verify_key)
        assert not interceptor.verify_signed_card(signed.jws_token, wrong_key)

    def test_verify_bad_format_fails(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        assert not interceptor.verify_signed_card("not.a.valid.jws.token", b"\x00" * 32)

    def test_to_well_known_response_has_jws(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        resp = signed.to_well_known_response()
        assert "_aevum_jws" in resp
        assert "_aevum_signed_at" in resp

    def test_to_well_known_response_has_card_fields(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        resp = signed.to_well_known_response()
        assert "name" in resp
        assert resp["name"] == "TestAgent"

    def test_to_well_known_response_no_kind_field(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        resp = signed.to_well_known_response()
        assert "kind" not in resp

    def test_jws_no_padding_in_token(self) -> None:
        kernel = _make_kernel()
        interceptor = AevumA2AInterceptor(kernel)
        signed = interceptor.sign_agent_card(_make_card())
        assert "=" not in signed.jws_token


class TestB64url:
    def test_roundtrip(self) -> None:
        data = b"hello world"
        assert _b64url_decode(_b64url(data)) == data

    def test_no_padding_chars(self) -> None:
        encoded = _b64url(b"test data")
        assert "=" not in encoded

    def test_url_safe_chars_only(self) -> None:
        encoded = _b64url(b"\xff\xfe\xfd")
        assert "+" not in encoded
        assert "/" not in encoded

    def test_empty_bytes(self) -> None:
        assert _b64url(b"") == ""

    def test_decode_empty(self) -> None:
        assert _b64url_decode("") == b""

    def test_roundtrip_binary(self) -> None:
        data = bytes(range(256))
        assert _b64url_decode(_b64url(data)) == data


class TestAevumAgentPackage:
    def test_package_exports_task_status(self) -> None:
        from aevum.agent import TaskStatus
        assert TaskStatus is not None

    def test_package_exports_a2a_task(self) -> None:
        from aevum.agent import A2ATask
        assert A2ATask is not None

    def test_package_exports_agent_card(self) -> None:
        from aevum.agent import AgentCard
        assert AgentCard is not None

    def test_package_exports_interceptor(self) -> None:
        from aevum.agent import AevumA2AInterceptor
        assert AevumA2AInterceptor is not None

    def test_package_exports_signed_task(self) -> None:
        from aevum.agent import SignedTask
        assert SignedTask is not None

    def test_package_exports_signed_agent_card(self) -> None:
        from aevum.agent import SignedAgentCard
        assert SignedAgentCard is not None

    def test_package_version(self) -> None:
        from aevum.agent import __version__
        assert __version__ == "0.7.3"

    def test_all_contains_expected_exports(self) -> None:
        import aevum.agent
        for name in (
            "A2ATask", "AgentCard", "TaskStatus", "AgentCapability",
            "AevumA2AInterceptor", "SignedTask", "SignedAgentCard",
        ):
            assert name in aevum.agent.__all__
