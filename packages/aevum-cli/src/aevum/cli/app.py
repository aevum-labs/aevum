# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Top-level typer app — CLI v2. Sub-commands and direct commands registered here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Any

import typer

from aevum.cli.commands import complication, conformance, server, store, version

# Module-level import for mock.patch patchability (Rule 57).
# Soft import: aevum-conformance is a workspace package not on PyPI, so
# callers without it installed still get a usable CLI (conform command
# shows a helpful error instead of crashing at startup).
try:
    from aevum.conformance.suite import ConformanceSuite
except ImportError:  # pragma: no cover
    ConformanceSuite = None  # type: ignore[assignment,misc]

app = typer.Typer(
    name="aevum",
    help="Aevum governed context kernel — CLI v2",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    rich_markup_mode="markdown",
)

app.add_typer(server.app, name="server")
app.add_typer(store.app, name="store")
app.add_typer(complication.app, name="complication")
app.add_typer(conformance.app, name="conformance")
app.command(name="version")(version.version_command)

_DEFAULT_STATE = Path.home() / ".aevum"


@app.command()
def init(
    state_dir: Annotated[
        Path,
        typer.Option("--state-dir", "-s", help="State directory path"),
    ] = _DEFAULT_STATE,
    principles: Annotated[
        Path,
        typer.Option("--principles", "-p", help="Path to signed_principles.yaml"),
    ] = Path("signed_principles.yaml"),
) -> None:
    """
    Initialize Aevum state directory and verify principles.

    Creates the state directory, generates dual signing keys (Ed25519 +
    ML-DSA-65), and verifies the signed_principles.yaml file.
    """
    typer.echo(f"Initializing Aevum state at {state_dir}...")

    try:
        from aevum.core.principles import PrinciplesVerifier
        verifier = PrinciplesVerifier(principles)
        p = verifier.verify()
        typer.echo(f"  Principles: OK (sequence={p.sequence}, signed_by={p.signed_by[:30]}...)")
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"  Principles: FAILED — {exc}", err=True)
        raise typer.Exit(code=1) from None

    try:
        from aevum.core.kernel import Kernel
        kernel = Kernel.local(
            state_dir=state_dir,
            principles_path=principles,
            tsa_enabled=False,
        )
        ed25519_pub = kernel.signer.ed25519_public_key.hex()[:16]
        typer.echo(f"  Keys: OK (ed25519={ed25519_pub}...)")
        typer.echo(f"  Canaries: PASS ({len(kernel.principles.immutable_ids())} immutable principles)")
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"  Kernel init: FAILED — {exc}", err=True)
        raise typer.Exit(code=1) from None

    typer.echo(typer.style("Aevum initialized successfully.", fg=typer.colors.GREEN))


@app.command()
def verify(
    session_id: Annotated[str, typer.Argument(help="Session ID to verify")],
    state_dir: Annotated[
        Path,
        typer.Option("--state-dir", "-s"),
    ] = _DEFAULT_STATE,
) -> None:
    """
    Verify a session's Merkle root and signatures.

    Re-reads the stored session events from SQLite, recomputes the
    Merkle root, and compares it to the signed root in the sigchain.
    """
    db_path = state_dir / "aevum.db"
    if not db_path.exists():
        typer.echo(f"Database not found: {db_path}", err=True)
        raise typer.Exit(code=1)

    try:
        from aevum.core.replay import ReplayEngine
        engine = ReplayEngine(db_path)
        result = engine.replay(session_id)

        if result.all_matched:
            typer.echo(typer.style(
                f"Session {session_id[:8]}... VERIFIED",
                fg=typer.colors.GREEN,
            ))
            typer.echo(f"  Merkle root: {result.original_merkle_root[:16]}...")
            typer.echo(f"  Events: {len(result.event_results)}")
        else:
            typer.echo(typer.style(
                f"Session {session_id[:8]}... TAMPERED",
                fg=typer.colors.RED,
            ), err=True)
            typer.echo(
                f"  First divergence: event #{result.first_divergence}", err=True
            )
            raise typer.Exit(code=1)

    except ValueError as exc:
        typer.echo(f"Session not found: {exc}", err=True)
        raise typer.Exit(code=1) from None


@app.command(name="audit-pack")
def audit_pack(
    session_id: Annotated[str, typer.Argument(help="Session ID")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path (default: stdout)"),
    ] = None,
    state_dir: Annotated[
        Path,
        typer.Option("--state-dir", "-s"),
    ] = _DEFAULT_STATE,
) -> None:
    """
    Export EU AI Act Article 12 audit pack for a session.

    Produces a JSON-LD document using the PROV-O vocabulary.
    """
    db_path = state_dir / "aevum.db"
    if not db_path.exists():
        typer.echo(f"Database not found: {db_path}", err=True)
        raise typer.Exit(code=1)

    try:
        from aevum.core.audit.audit_pack import AuditPackExporter
        exporter = AuditPackExporter(db_path)
        json_text = exporter.export_json(session_id)

        if output:
            output.write_text(json_text, encoding="utf-8")
            typer.echo(f"Audit pack written to {output}")
        else:
            typer.echo(json_text)

    except Exception as exc:  # noqa: BLE001
        typer.echo(f"Audit pack error: {exc}", err=True)
        raise typer.Exit(code=1) from None


@app.command()
def conform(
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: text or json"),
    ] = "text",
) -> None:
    """
    Run the 9-invariant conformance suite.

    Tests all required Aevum behavioral invariants and prints a report.
    Exit code 0 = all pass, 1 = one or more fail.
    """
    if ConformanceSuite is None:
        typer.echo(
            "aevum-conformance is not installed. Install it with: pip install aevum-conformance",
            err=True,
        )
        raise typer.Exit(code=1)
    suite = ConformanceSuite()
    result = suite.run_all()

    if output == "json":
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        typer.echo(result.render())

    if not result.all_passed:
        raise typer.Exit(code=1)


@app.command(name="verify-receipt")
def verify_receipt(
    receipt_file: Annotated[Path, typer.Argument(help="Path to COSE_Sign1 receipt file")],
) -> None:
    """
    Verify an Aevum COSE_Sign1 receipt file.

    Decodes the receipt, verifies the Ed25519 signature over the canonical payload,
    and prints a human-readable summary. Exit 0 on valid, exit 1 on invalid signature.
    """
    import cbor2
    import nacl.exceptions
    import nacl.signing
    from aevum.core.receipt import AevumReceipt

    if not receipt_file.exists():
        typer.echo(f"File not found: {receipt_file}", err=True)
        raise typer.Exit(code=1)

    raw = receipt_file.read_bytes()

    try:
        cose = cbor2.loads(raw)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"INVALID: not a valid CBOR file: {exc}", err=True)
        raise typer.Exit(code=1) from None

    if not isinstance(cose, list) or len(cose) != 4:
        typer.echo("INVALID: not a 4-element COSE_Sign1 array", err=True)
        raise typer.Exit(code=1)

    protected_bstr, unprotected, payload_bstr, signature_bytes = cose

    try:
        protected = cbor2.loads(protected_bstr)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"INVALID: cannot decode protected header: {exc}", err=True)
        raise typer.Exit(code=1) from None

    alg = protected.get(1)
    if alg != -8:
        typer.echo(f"UNSUPPORTED ALGORITHM: alg={alg!r} (expected -8 for EdDSA/Ed25519)", err=True)
        raise typer.Exit(code=2) from None

    try:
        receipt_data = cbor2.loads(payload_bstr)
        receipt = AevumReceipt.model_validate(receipt_data)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"INVALID: cannot decode receipt payload: {exc}", err=True)
        raise typer.Exit(code=1) from None

    # Reconstruct Sig_Structure and verify signature
    sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
    digest = hashlib.sha3_256(sig_structure).digest()

    # Try to find Ed25519 public key from state dir (kid field in protected header reserved for future)
    pub_key_bytes: bytes | None = None
    state_dir = Path.home() / ".aevum"
    ed25519_pub_path = state_dir / "ed25519.pub"
    if ed25519_pub_path.exists():
        pub_key_bytes = ed25519_pub_path.read_bytes()

    if pub_key_bytes is None:
        typer.echo(
            "WARNING: no public key found in ~/.aevum/ed25519.pub — skipping signature check.",
            err=True,
        )
        typer.echo("WARNING: receipt content is displayed but authenticity is NOT verified.", err=True)
        verified = False
    else:
        try:
            verify_key = nacl.signing.VerifyKey(pub_key_bytes)
            verify_key.verify(digest, bytes(signature_bytes))
            verified = True
        except nacl.exceptions.BadSignatureError:
            typer.echo("SIGNATURE INVALID", err=True)
            _print_receipt_summary(receipt, unprotected, verified=False)
            raise typer.Exit(code=1) from None
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"SIGNATURE INVALID: {exc}", err=True)
            raise typer.Exit(code=1) from None

    _print_receipt_summary(receipt, unprotected, verified=verified)


def _print_receipt_summary(
    receipt: Any,
    unprotected: dict,  # type: ignore[type-arg]
    verified: bool,
) -> None:
    """Print human-readable receipt summary."""

    status_line = "✓ Aevum Receipt Verified" if verified else "! Aevum Receipt (unverified)"
    typer.echo(status_line)
    typer.echo("─" * 36)

    tsa_info = "none"
    if 9 in unprotected:
        tsa_info = f"<RFC 3161 token, {len(unprotected[9])} bytes>"

    barriers_summary = (
        ", ".join(f"{k}:{v}" for k, v in receipt.barrier_evaluations.items())
        if receipt.barrier_evaluations
        else "none"
    )

    prior_display = receipt.prior_hash[:12] if len(receipt.prior_hash) >= 12 else receipt.prior_hash
    model_display = receipt.model_identity_hash[:12] if len(receipt.model_identity_hash) >= 12 else receipt.model_identity_hash

    typer.echo(f"Action:         {receipt.action}")
    typer.echo(f"Agent:          {receipt.agent_id}")
    typer.echo(f"Principal:      {receipt.principal}")
    typer.echo(f"Occurred at:    {receipt.occurred_at}")
    typer.echo(f"Sequence:       {receipt.sequence}")
    typer.echo(f"Prior hash:     {prior_display}...")
    typer.echo(f"Handoff type:   {receipt.handoff_type or 'none'}")
    typer.echo(f"Model hash:     {model_display}...")
    typer.echo(f"Policy version: {receipt.policy_version}")
    typer.echo(f"TSA timestamp:  {tsa_info}")
    typer.echo(f"Barriers:       {barriers_summary}")


@app.command()
def replay(
    session_id: Annotated[str, typer.Argument(help="Session ID to replay")],
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show per-event results"),
    ] = False,
    state_dir: Annotated[
        Path,
        typer.Option("--state-dir", "-s"),
    ] = _DEFAULT_STATE,
) -> None:
    """
    Replay a session and verify Merkle chain integrity.

    Re-reads all events and recomputes the Merkle root. Reports any
    divergence from the stored root (indicating tampering).
    """
    db_path = state_dir / "aevum.db"
    if not db_path.exists():
        typer.echo(f"Database not found: {db_path}", err=True)
        raise typer.Exit(code=1)

    try:
        from aevum.core.replay import ReplayEngine
        engine = ReplayEngine(db_path)
        result = engine.replay(session_id)

        status = (
            typer.style("PASS", fg=typer.colors.GREEN)
            if result.all_matched
            else typer.style("FAIL", fg=typer.colors.RED)
        )
        typer.echo(f"Replay {session_id[:8]}...: {status}")
        typer.echo(f"  Events: {len(result.event_results)}")
        typer.echo(f"  Merkle root: {result.original_merkle_root[:16]}...")

        if verbose:
            for ev in result.event_results:
                ev_status = "OK" if ev.matched else "DIVERGED"
                typer.echo(f"  [{ev.sequence:3d}] {ev.event_type:<12} {ev_status}")

        if not result.all_matched:
            typer.echo(
                f"  First divergence: event #{result.first_divergence}", err=True
            )
            raise typer.Exit(code=1)

    except ValueError as exc:
        typer.echo(f"Session not found: {exc}", err=True)
        raise typer.Exit(code=1) from None
