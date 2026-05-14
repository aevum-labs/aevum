# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
Top-level typer app — CLI v2. Sub-commands and direct commands registered here.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from aevum.cli.commands import complication, conformance, server, store, version
from aevum.conformance.suite import ConformanceSuite  # module-level for mock.patch (Rule 57)

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
        raise typer.Exit(code=1)

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
        raise typer.Exit(code=1)

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
        raise typer.Exit(code=1)


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
        raise typer.Exit(code=1)


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
    suite = ConformanceSuite()
    result = suite.run_all()

    if output == "json":
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        typer.echo(result.render())

    if not result.all_passed:
        raise typer.Exit(code=1)


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
        raise typer.Exit(code=1)
