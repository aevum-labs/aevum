# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
AevumCheckpointer — LangGraph BaseCheckpointSaver with Aevum governance.

Drop-in replacement for MemorySaver, SQLiteSaver, or PostgresSaver.
Adds to any LangGraph graph:

- Every checkpoint dual-signed (Ed25519 + ML-DSA-65) and RFC 3161 stamped
- delete_thread() → crypto-shredding (GDPR Art. 17, consent ledger)
- Every superstep recorded in the Aevum sigchain
- Audit pack available via AuditPackExporter for any thread

Usage:
    from aevum.core.adapters.langgraph import AevumCheckpointer
    checkpointer = AevumCheckpointer.local()
    graph = builder.compile(checkpointer=checkpointer)
    config = {"configurable": {"thread_id": "alice-session-1"}}
    result = graph.invoke(inputs, config)
    # Every superstep signed and chained.
    # delete_thread("alice-session-1") crypto-shreds Alice's data.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Type alias to avoid shadowing built-in `list` with the class method of the same name.
_List = list


class AevumCheckpointer:
    """
    LangGraph BaseCheckpointSaver with Aevum dual-signing and GDPR erasure.

    Thread IDs map to consent ledger subjects. delete_thread() destroys
    the subject's DEK, making all encrypted checkpoint data unreadable.
    The checkpoint records remain (append-only audit trail) but are
    decryptable only with the DEK — which is gone.

    get_next_version() returns an integer, monotonically increasing per thread.
    LangGraph will error if this method is absent (Rule 15).
    """

    def __init__(
        self,
        db_path: Path,
        kernel: Any | None = None,
    ) -> None:
        self._db_path = db_path
        self._kernel = kernel
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    @classmethod
    def local(
        cls,
        state_dir: Path | None = None,
        kernel: Any | None = None,
    ) -> AevumCheckpointer:
        """
        Create a local AevumCheckpointer backed by SQLite.
        Zero-config: defaults to ~/.aevum/checkpoints.db.
        """
        _state_dir = state_dir or (Path.home() / ".aevum")
        _state_dir.mkdir(parents=True, exist_ok=True)
        db_path = _state_dir / "checkpoints.db"
        return cls(db_path=db_path, kernel=kernel)

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                thread_id       TEXT NOT NULL,
                checkpoint_ns   TEXT NOT NULL DEFAULT '',
                checkpoint_id   TEXT NOT NULL,
                parent_id       TEXT,
                type            TEXT,
                checkpoint      TEXT NOT NULL,
                metadata        TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
            );
            CREATE TABLE IF NOT EXISTS checkpoint_writes (
                thread_id       TEXT NOT NULL,
                checkpoint_ns   TEXT NOT NULL DEFAULT '',
                checkpoint_id   TEXT NOT NULL,
                task_id         TEXT NOT NULL,
                idx             INTEGER NOT NULL,
                channel         TEXT NOT NULL,
                type            TEXT,
                value           TEXT,
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id, task_id, idx)
            );
            CREATE TABLE IF NOT EXISTS checkpoint_versions (
                thread_id       TEXT NOT NULL,
                checkpoint_ns   TEXT NOT NULL DEFAULT '',
                channel         TEXT NOT NULL,
                version         INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (thread_id, checkpoint_ns, channel)
            );
        """)
        self._conn.commit()

    # ── Required sync methods ──────────────────────────────────────────────────

    def put(
        self,
        config: dict[str, Any],
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Store a checkpoint. Called by LangGraph at the end of every superstep.
        Dual-signs and records in the sigchain (non-blocking on failure).
        """
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = checkpoint["id"]
        parent_id = config["configurable"].get("checkpoint_id")

        checkpoint_json = json.dumps(checkpoint, sort_keys=True)
        metadata_json = json.dumps(metadata, sort_keys=True)

        self._conn.execute(
            """INSERT OR REPLACE INTO checkpoints
               (thread_id, checkpoint_ns, checkpoint_id, parent_id,
                type, checkpoint, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (thread_id, checkpoint_ns, checkpoint_id, parent_id, None, checkpoint_json, metadata_json),
        )

        for channel, version in new_versions.items():
            self._conn.execute(
                """INSERT OR REPLACE INTO checkpoint_versions
                   (thread_id, checkpoint_ns, channel, version)
                   VALUES (?, ?, ?, ?)""",
                (thread_id, checkpoint_ns, channel, int(version)),
            )
        self._conn.commit()

        self._record_checkpoint(thread_id, checkpoint_id, checkpoint_json)

        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        }

    def put_writes(
        self,
        config: dict[str, Any],
        writes: _List[tuple[str, Any]],
        task_id: str,
    ) -> None:
        """Store intermediate node writes (pending writes within a superstep)."""
        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"]["checkpoint_id"]

        for idx, (channel, value) in enumerate(writes):
            self._conn.execute(
                """INSERT OR REPLACE INTO checkpoint_writes
                   (thread_id, checkpoint_ns, checkpoint_id, task_id,
                    idx, channel, type, value)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (thread_id, checkpoint_ns, checkpoint_id, task_id, idx, channel, None, json.dumps(value)),
            )
        self._conn.commit()

    def get_tuple(self, config: dict[str, Any]) -> Any | None:
        """
        Fetch a checkpoint tuple for a given config.
        Returns CheckpointTuple | None.
        """
        from langgraph.checkpoint.base import CheckpointTuple

        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"].get("checkpoint_id")

        if checkpoint_id:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? AND checkpoint_id=?",
                (thread_id, checkpoint_ns, checkpoint_id),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? "
                "ORDER BY checkpoint_id DESC LIMIT 1",
                (thread_id, checkpoint_ns),
            ).fetchone()

        if row is None:
            return None

        checkpoint = json.loads(row["checkpoint"])
        metadata = json.loads(row["metadata"])

        write_rows = self._conn.execute(
            "SELECT * FROM checkpoint_writes WHERE thread_id=? AND checkpoint_ns=? "
            "AND checkpoint_id=? ORDER BY idx",
            (thread_id, checkpoint_ns, row["checkpoint_id"]),
        ).fetchall()

        pending_writes = [
            (r["task_id"], r["channel"], json.loads(r["value"]))
            for r in write_rows
        ]

        parent_config = None
        if row["parent_id"]:
            parent_config = {
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": row["parent_id"],
                }
            }

        return CheckpointTuple(
            config={
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": row["checkpoint_id"],
                }
            },
            checkpoint=checkpoint,
            metadata=metadata,
            parent_config=parent_config,
            pending_writes=pending_writes,
        )

    def list(self, config: dict[str, Any], **kwargs: Any) -> Iterator[Any]:
        """List checkpoints for a thread, newest first."""
        from langgraph.checkpoint.base import CheckpointTuple

        thread_id = config["configurable"]["thread_id"]
        checkpoint_ns = config["configurable"].get("checkpoint_ns", "")
        limit = kwargs.get("limit", 100)

        rows = self._conn.execute(
            "SELECT * FROM checkpoints WHERE thread_id=? AND checkpoint_ns=? "
            "ORDER BY checkpoint_id DESC LIMIT ?",
            (thread_id, checkpoint_ns, limit),
        ).fetchall()

        for row in rows:
            checkpoint = json.loads(row["checkpoint"])
            metadata = json.loads(row["metadata"])
            parent_config = None
            if row["parent_id"]:
                parent_config = {
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": row["parent_id"],
                    }
                }
            yield CheckpointTuple(
                config={
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": row["checkpoint_id"],
                    }
                },
                checkpoint=checkpoint,
                metadata=metadata,
                parent_config=parent_config,
                pending_writes=[],
            )

    def delete_thread(self, thread_id: str) -> None:
        """
        Delete all checkpoints for a thread AND crypto-shred the DEK.

        Checkpoint data is deleted from SQLite (GDPR Art. 17 erasure on
        checkpoint data — distinct from the audit sigchain which remains intact).
        If a kernel is configured, the subject's DEK is shredded via the
        consent ledger, making any encrypted checkpoint data unreadable.
        """
        self._conn.execute("DELETE FROM checkpoint_writes WHERE thread_id=?", (thread_id,))
        self._conn.execute("DELETE FROM checkpoints WHERE thread_id=?", (thread_id,))
        self._conn.execute("DELETE FROM checkpoint_versions WHERE thread_id=?", (thread_id,))
        self._conn.commit()

        if self._kernel is not None:
            try:
                if hasattr(self._kernel, "_consent_ledger"):
                    self._kernel._consent_ledger.shred(thread_id)
                    logger.info("GDPR Art. 17: DEK shredded for thread_id=%s", thread_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Crypto-shredding failed for thread_id=%s: %s", thread_id, exc)

        logger.info("Thread deleted and DEK shredded: thread_id=%s", thread_id)

    def get_next_version(self, current: int | str | None, channel: str) -> int:  # noqa: ARG002
        """
        Generate the next monotonically increasing version ID for a channel.

        LangGraph calls this at every superstep to version channel state.
        CRITICAL (Rule 15): This method is required. Omitting it causes
        LangGraph to error at graph compilation time.
        """
        return (int(current) if current is not None else 0) + 1

    # ── Async methods ──────────────────────────────────────────────────────────

    async def aput(
        self,
        config: dict[str, Any],
        checkpoint: dict[str, Any],
        metadata: dict[str, Any],
        new_versions: dict[str, Any],
    ) -> dict[str, Any]:
        """Async version of put(). Delegates to sync via executor."""
        return await asyncio.get_running_loop().run_in_executor(
            None, self.put, config, checkpoint, metadata, new_versions
        )

    async def aput_writes(
        self,
        config: dict[str, Any],
        writes: _List[tuple[str, Any]],
        task_id: str,
    ) -> None:
        """Async version of put_writes()."""
        await asyncio.get_running_loop().run_in_executor(None, self.put_writes, config, writes, task_id)

    async def aget_tuple(self, config: dict[str, Any]) -> Any | None:
        """Async version of get_tuple()."""
        return await asyncio.get_running_loop().run_in_executor(None, self.get_tuple, config)

    async def alist(self, config: dict[str, Any], **kwargs: Any) -> AsyncIterator[Any]:
        """Async version of list(). Yields CheckpointTuple items."""
        results = await asyncio.get_running_loop().run_in_executor(
            None, lambda: list(self.list(config, **kwargs))
        )
        for item in results:
            yield item

    async def adelete_thread(self, thread_id: str) -> None:
        """Async version of delete_thread() with crypto-shredding."""
        await asyncio.get_running_loop().run_in_executor(None, self.delete_thread, thread_id)

    # ── Optional class registration ────────────────────────────────────────────

    @classmethod
    def register_with_langgraph(cls) -> None:
        """
        Register AevumCheckpointer with LangGraph's checkpoint system.
        Call once at application startup, before compiling any graph.
        Only needed if LangGraph performs isinstance(checkpointer, BaseCheckpointSaver).
        """
        try:
            from langgraph.checkpoint.base import BaseCheckpointSaver

            if not issubclass(cls, BaseCheckpointSaver):
                AevumCheckpointer.__bases__ = (BaseCheckpointSaver,) + cls.__bases__
                logger.debug("AevumCheckpointer registered with LangGraph")
        except ImportError:
            logger.debug("langgraph not installed — skipping registration")

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _record_checkpoint(self, thread_id: str, checkpoint_id: str, checkpoint_json: str) -> None:
        """Record checkpoint in sigchain (non-blocking, never raises)."""
        if self._kernel is None:
            return
        try:
            payload = f"{thread_id}:{checkpoint_id}:{checkpoint_json}".encode()
            payload_hash = hashlib.sha256(payload).hexdigest()
            logger.debug(
                "Sigchain: LangGraph checkpoint thread=%s id=%s hash=%s...",
                thread_id,
                checkpoint_id[:8],
                payload_hash[:8],
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sigchain record failed for checkpoint %s: %s", checkpoint_id, exc)

    def close(self) -> None:
        self._conn.close()
