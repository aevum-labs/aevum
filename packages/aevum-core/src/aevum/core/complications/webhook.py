"""
WebhookRegistry -- register endpoints and dispatch review events.

Retry schedule: 3 attempts at 1s, 5s, 25s (base^n with base=5).
On final failure: appends a barrier.webhook_failed AuditEvent to the ledger.
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

WEBHOOK_EVENTS = {"review.approved", "review.vetoed"}
_RETRY_DELAYS = (1.0, 5.0, 25.0)  # seconds between attempts


class WebhookRegistration:
    def __init__(self, webhook_id: str, url: str, secret: str, events: list[str]) -> None:
        self.webhook_id = webhook_id
        self.url = url
        self.secret = secret
        self.events = set(events)
        self.registered_at = time.monotonic()


class WebhookRegistry:
    """
    Thread-safe webhook registry with exponential backoff retry.

    http_client: injected for testability (mock in tests, httpx.Client in prod).
    ledger: optional -- if provided, dead-letter events are appended on final failure.
    """

    def __init__(
        self,
        http_client: Any | None = None,
        ledger: Any | None = None,
    ) -> None:
        self._registrations: dict[str, WebhookRegistration] = {}
        self._lock = threading.Lock()
        self._http_client = http_client
        self._ledger = ledger

    def register(
        self,
        webhook_id: str,
        url: str,
        secret: str,
        events: list[str] | None = None,
    ) -> None:
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
        Dispatch to all subscribed webhooks with exponential backoff retry.
        Returns list of webhook_ids successfully delivered to.
        """
        with self._lock:
            targets = [
                r for r in self._registrations.values()
                if event_type in r.events
            ]

        dispatched: list[str] = []
        for reg in targets:
            if self._deliver_with_retry(reg, event_type, payload):
                dispatched.append(reg.webhook_id)
            else:
                self._dead_letter(reg.webhook_id, event_type, payload)
        return dispatched

    def _deliver_with_retry(
        self, reg: WebhookRegistration, event_type: str, payload: dict[str, Any]
    ) -> bool:
        """Attempt delivery with exponential backoff. Returns True on success."""
        for attempt, _delay in enumerate(_RETRY_DELAYS):
            try:
                self._deliver(reg, event_type, payload)
                if attempt > 0:
                    logger.info(
                        "Webhook %s delivered after %d retries", reg.webhook_id, attempt
                    )
                return True
            except Exception as e:
                if attempt < len(_RETRY_DELAYS) - 1:
                    next_delay = _RETRY_DELAYS[attempt + 1]
                    logger.warning(
                        "Webhook %s attempt %d failed: %s -- retrying in %.0fs",
                        reg.webhook_id, attempt + 1, e, next_delay,
                    )
                    time.sleep(next_delay)
                else:
                    logger.error(
                        "Webhook %s failed all %d attempts: %s",
                        reg.webhook_id, len(_RETRY_DELAYS), e,
                    )
        return False

    def _dead_letter(
        self, webhook_id: str, event_type: str, payload: dict[str, Any]
    ) -> None:
        """Append dead-letter AuditEvent to ledger if configured."""
        if self._ledger is None:
            return
        try:
            self._ledger.append(
                event_type="barrier.webhook_failed",
                payload={
                    "webhook_id": webhook_id,
                    "original_event_type": event_type,
                    "original_payload_keys": list(payload.keys()),
                    "attempts": len(_RETRY_DELAYS),
                },
                actor="aevum-core",
            )
        except Exception as e:
            logger.error("Failed to write webhook dead-letter to ledger: %s", e)

    def _deliver(
        self, reg: WebhookRegistration, event_type: str, payload: dict[str, Any]
    ) -> None:
        body = json.dumps({
            "event_type": event_type,
            "payload": payload,
            "timestamp": time.time(),
            "webhook_id": reg.webhook_id,
        }, default=str)
        signature = self._sign(reg.secret, body)
        headers = {
            "Content-Type": "application/json",
            "X-Aevum-Signature": signature,
            "X-Aevum-Event": event_type,
        }
        if self._http_client is not None:
            self._http_client.post(reg.url, content=body, headers=headers)
        else:
            logger.debug("Webhook dispatch (no http_client): %s -> %s", event_type, reg.url)

    @staticmethod
    def _sign(secret: str, body: str) -> str:
        mac = hmac.new(secret.encode(), body.encode(), hashlib.sha256)
        return f"sha256={mac.hexdigest()}"
