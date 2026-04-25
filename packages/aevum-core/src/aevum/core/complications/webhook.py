"""
WebhookRegistry — register endpoints and dispatch review events.

Spec Section 10 (deferred from Phase 3b).
Implements registration and dispatch interface.
HTTP delivery is testable via mock injection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Events that trigger webhook delivery
WEBHOOK_EVENTS = {"review.approved", "review.vetoed"}


class WebhookRegistration:
    def __init__(
        self,
        webhook_id: str,
        url: str,
        secret: str,
        events: list[str],
    ) -> None:
        self.webhook_id = webhook_id
        self.url = url
        self.secret = secret
        self.events = set(events)
        self.registered_at = time.monotonic()


class WebhookRegistry:
    """
    Thread-safe webhook registry.

    Webhooks are registered per-event-type. When a matching event
    occurs, dispatch() is called with the event payload.

    HTTP delivery is injected via `http_client` to allow mocking in tests.
    In production, pass an httpx.Client or similar.
    """

    def __init__(
        self,
        http_client: Any | None = None,
    ) -> None:
        self._registrations: dict[str, WebhookRegistration] = {}
        self._lock = threading.Lock()
        self._http_client = http_client  # injected; None = no real delivery

    def register(
        self,
        webhook_id: str,
        url: str,
        secret: str,
        events: list[str] | None = None,
    ) -> None:
        """Register a webhook endpoint."""
        if not url.startswith("https://") and not url.startswith("http://localhost"):
            raise ValueError("Webhook URL must use HTTPS (or http://localhost for dev)")
        with self._lock:
            self._registrations[webhook_id] = WebhookRegistration(
                webhook_id=webhook_id,
                url=url,
                secret=secret,
                events=events or list(WEBHOOK_EVENTS),
            )

    def deregister(self, webhook_id: str) -> None:
        with self._lock:
            self._registrations.pop(webhook_id, None)

    def all_registrations(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"webhook_id": r.webhook_id, "url": r.url, "events": list(r.events)}
                for r in self._registrations.values()
            ]

    def dispatch(self, event_type: str, payload: dict[str, Any]) -> list[str]:
        """
        Dispatch an event to all registered webhooks that subscribe to it.

        Returns list of webhook_ids that were dispatched to.
        Failures are logged but do not raise — delivery is best-effort.
        """
        with self._lock:
            targets = [
                r for r in self._registrations.values()
                if event_type in r.events
            ]

        dispatched: list[str] = []
        for registration in targets:
            try:
                self._deliver(registration, event_type, payload)
                dispatched.append(registration.webhook_id)
            except Exception as e:
                logger.warning(
                    "Webhook delivery failed for %s → %s: %s",
                    registration.webhook_id, registration.url, e,
                )
        return dispatched

    def _deliver(
        self,
        registration: WebhookRegistration,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        """Deliver one webhook. Uses injected http_client if present."""
        body = json.dumps({
            "event_type": event_type,
            "payload": payload,
            "timestamp": time.time(),
            "webhook_id": registration.webhook_id,
        }, default=str)

        signature = self._sign(registration.secret, body)
        headers = {
            "Content-Type": "application/json",
            "X-Aevum-Signature": signature,
            "X-Aevum-Event": event_type,
        }

        if self._http_client is not None:
            self._http_client.post(
                registration.url, content=body, headers=headers
            )
        else:
            logger.debug(
                "Webhook dispatch (no http_client configured): %s → %s",
                event_type, registration.url,
            )

    @staticmethod
    def _sign(secret: str, body: str) -> str:
        """HMAC-SHA256 signature over the body. Spec Section 10."""
        mac = hmac.new(secret.encode(), body.encode(), hashlib.sha256)
        return f"sha256={mac.hexdigest()}"
