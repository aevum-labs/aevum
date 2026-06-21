# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

import pytest

from aevum.core.audit.event import AuditEvent
from aevum.core.audit.evidence_pack import (
    EvidencePackError,
    export_evidence_pack,
)
from aevum.core.audit.sigchain import Sigchain


def _build_chain(n: int = 2) -> tuple[Sigchain, list[AuditEvent]]:
    chain = Sigchain()
    events = [
        chain.new_event(
            event_type="consent.granted",
            payload={"subject": f"DEMO-{i}", "synthetic": True},
            actor="test-suite",
        )
        for i in range(n)
    ]
    return chain, events


def test_export_evidence_pack_writes_all_files(tmp_path: Path) -> None:
    chain, events = _build_chain()
    out = export_evidence_pack(
        events, tmp_path / "pack", ed25519_pub=chain._signer.public_key_bytes()
    )
    assert out == tmp_path / "pack"
    names = {p.name for p in out.iterdir()}
    assert names == {"chain.json", "ed25519-pub.hex", "manifest.json", "VERIFY.txt"}


def test_export_evidence_pack_chain_json_is_full_fidelity(tmp_path: Path) -> None:
    chain, events = _build_chain()
    out = export_evidence_pack(
        events, tmp_path / "pack", ed25519_pub=chain._signer.public_key_bytes()
    )
    entries = json.loads((out / "chain.json").read_text())
    assert len(entries) == len(events)
    for entry, event in zip(entries, events, strict=True):
        assert entry["event_id"] == event.event_id
        assert entry["signature"] == event.signature
        assert entry["payload_hash"] == event.payload_hash
        assert entry["prior_hash"] == event.prior_hash
        # the scrubbed public-demo shape has no signature at all — guard against
        # ever regressing to that shape here.
        assert entry["signature"] is not None
        assert "receipt_cbor" not in entry


def test_export_evidence_pack_pins_ed25519_key(tmp_path: Path) -> None:
    chain, events = _build_chain()
    pub = chain._signer.public_key_bytes()
    out = export_evidence_pack(events, tmp_path / "pack", ed25519_pub=pub)
    assert (out / "ed25519-pub.hex").read_text() == pub.hex() + "\n"
    assert not (out / "mldsa65-pub.hex").exists()


def test_export_evidence_pack_manifest_fields(tmp_path: Path) -> None:
    chain, events = _build_chain()
    out = export_evidence_pack(
        events, tmp_path / "pack", ed25519_pub=chain._signer.public_key_bytes()
    )
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["format"] == "aevum-evidence-pack-v1"
    assert manifest["entry_count"] == len(events)
    assert manifest["key_id"] == events[-1].signer_key_id
    assert manifest["key_scheme"] == "ed25519"
    assert manifest["chain_id"] == AuditEvent.hash_event_for_chain(events[-1])
    assert manifest["verifier_package"] == "aevum-verify"
    assert "created_at" in manifest
    # no secrets: the manifest must never carry raw keys or signatures
    blob = json.dumps(manifest)
    assert events[-1].signature not in blob


def test_export_evidence_pack_verify_txt_cites_standalone_package_only(
    tmp_path: Path,
) -> None:
    chain, events = _build_chain()
    out = export_evidence_pack(
        events, tmp_path / "pack", ed25519_pub=chain._signer.public_key_bytes()
    )
    text = (out / "VERIFY.txt").read_text()
    assert "pip install aevum-verify" in text
    assert "aevum-cli" in text  # explicitly called out as NOT the independent path
    assert "aevum-verify chain.json" in text
    assert "VERIFIED" in text
    assert "FAILED" in text


def test_export_evidence_pack_hybrid_includes_mldsa_pub(tmp_path: Path) -> None:
    chain, events = _build_chain()
    mldsa_pub = b"\x01" * 1952  # ML-DSA-65 public key length; content irrelevant here
    out = export_evidence_pack(
        events,
        tmp_path / "pack",
        ed25519_pub=chain._signer.public_key_bytes(),
        mldsa65_pub=mldsa_pub,
    )
    assert (out / "mldsa65-pub.hex").read_text() == mldsa_pub.hex() + "\n"
    manifest = json.loads((out / "manifest.json").read_text())
    assert "--mldsa65-pub" in manifest["verify_command"]
    text = (out / "VERIFY.txt").read_text()
    assert "[pqc]" in text


def test_export_evidence_pack_rejects_empty_chain(tmp_path: Path) -> None:
    with pytest.raises(EvidencePackError):
        export_evidence_pack([], tmp_path / "pack", ed25519_pub=b"\x00" * 32)


def test_export_evidence_pack_creates_out_dir(tmp_path: Path) -> None:
    chain, events = _build_chain()
    nested = tmp_path / "a" / "b" / "pack"
    out = export_evidence_pack(events, nested, ed25519_pub=chain._signer.public_key_bytes())
    assert out.is_dir()
