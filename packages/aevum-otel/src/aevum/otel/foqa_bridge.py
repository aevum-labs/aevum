# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
FOQABridge: connects ExceedanceDetector events to OTel aggregate metrics.

Emits counter metrics per exceedance type.
Does NOT emit individual event data — only aggregate counts (de-identified).
This is the "aggregate FOQA data sent to the FAA" equivalent (FAA AC 120-82).

OTel metric names:
  aevum.exceedance.count  — counter, dimensions: exceedance_id, severity
  aevum.session.count     — counter (total sessions observed)

Privacy note: session_id and agent_id are intentionally NOT emitted in metric
attributes, even pseudonymized. A pseudonymized session_id in a high-cardinality
OTel metric would allow correlation attacks if the attacker has external session
timing data. Aggregates only means: count, not "which sessions."
"""

from __future__ import annotations

from typing import Any

from aevum.core.exceedance import ExceedanceEvent
from opentelemetry import metrics

from aevum.otel.gatekeeper import GatekeeperFilter


class FOQABridge:
    """
    Receives ExceedanceEvents and emits de-identified OTel aggregate metrics.
    One FOQABridge per deployment (not per session).

    Usage:
        bridge = FOQABridge(gatekeeper=GatekeeperFilter())
        # In your agent session loop:
        for exc in detector.exceedances():
            bridge.record(exc)
        bridge.record_session_start()
    """

    def __init__(
        self,
        gatekeeper: GatekeeperFilter,
        meter_name: str = "aevum.foqa",
        meter_version: str = "0.7.0",
        meter_provider: Any | None = None,
    ) -> None:
        self._gatekeeper = gatekeeper
        mp = meter_provider if meter_provider is not None else metrics.get_meter_provider()
        meter = mp.get_meter(meter_name, meter_version)
        self._exceedance_counter = meter.create_counter(
            name="aevum.exceedance.count",
            description="Number of FOQA exceedances detected by type",
            unit="1",
        )
        self._session_counter = meter.create_counter(
            name="aevum.session.count",
            description="Total agent sessions observed by the FOQA bridge",
            unit="1",
        )

    def record(self, event: ExceedanceEvent) -> None:
        """
        Record a de-identified ExceedanceEvent as an OTel metric.
        The event is filtered through GatekeeperFilter before any data is used.
        NEVER emits the original session_id, agent_id, or receipt_hash.
        """
        # De-identify first — then emit
        filtered = self._gatekeeper.filter_exceedance(event)
        self._exceedance_counter.add(
            1,
            attributes={
                "exceedance_id": filtered.exceedance_id,
                "exceedance_name": filtered.exceedance_name,
                "severity": filtered.severity,
                # session_id and agent_id are intentionally NOT included.
                # Even pseudonymized, high-cardinality session attributes
                # enable correlation attacks via external timing data.
            },
        )

    def record_session_start(self) -> None:
        """Call once per session start to track total session count."""
        self._session_counter.add(1)
