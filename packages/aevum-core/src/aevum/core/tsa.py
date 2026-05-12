# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
RFC 3161 timestamping client for the Aevum sigchain.

Uses rfc3161-client (Trail of Bits) for binary encoding/decoding.
Uses httpx for the actual HTTP network calls.

Default TSA: Sigstore TSA (OpenSSF-operated)
  POST https://timestamp.sigstore.dev/api/v1/timestamp
  Content-Type: application/timestamp-query

Fallback TSA: DigiCert
  http://timestamp.digicert.com

Design notes:
  - rfc3161-client makes no network calls — it is a pure codec library.
  - TSA calls are optional in tests (mock httpx or skip with --no-tsa flag).
  - A circuit breaker prevents TSA failures from blocking sigchain writes.
    On TSA timeout/error, the entry is written with tsa_token=None and
    a warning is logged. The entry is still valid (just without external time).
"""
from __future__ import annotations

import dataclasses
import logging

import httpx
from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response

logger = logging.getLogger(__name__)

# Default TSA configuration
SIGSTORE_TSA_URL = "https://timestamp.sigstore.dev/api/v1/timestamp"
DIGICERT_TSA_URL = "http://timestamp.digicert.com"

DEFAULT_TSA_URLS: list[str] = [
    SIGSTORE_TSA_URL,
    DIGICERT_TSA_URL,
]

TSA_TIMEOUT_SECONDS = 10.0
TSA_CONTENT_TYPE = "application/timestamp-query"


@dataclasses.dataclass(frozen=True)
class TSAToken:
    """
    The result of a successful RFC 3161 timestamp request.
    token_bytes is the raw DER-encoded TimeStampResponse.
    Store this alongside the sigchain entry.
    """
    tsa_url: str
    token_bytes: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "tsa_url": self.tsa_url,
            "token_bytes": self.token_bytes.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> TSAToken:
        return cls(
            tsa_url=d["tsa_url"],
            token_bytes=bytes.fromhex(d["token_bytes"]),
        )


class TSAClient:
    """
    Fetches RFC 3161 timestamps from a TSA server.

    On failure, the circuit breaker allows the sigchain to continue
    without a timestamp token rather than blocking.
    """

    def __init__(
        self,
        tsa_urls: list[str] | None = None,
        timeout: float = TSA_TIMEOUT_SECONDS,
        enabled: bool = True,
    ) -> None:
        self._tsa_urls = tsa_urls or DEFAULT_TSA_URLS
        self._timeout = timeout
        self._enabled = enabled

    def timestamp(self, data: bytes) -> TSAToken | None:
        """
        Request an RFC 3161 timestamp for data.

        Returns a TSAToken on success, or None if TSA is disabled or
        all TSA servers fail (circuit breaker — does not raise).

        The token_bytes is the raw DER-encoded TimeStampResponse.
        """
        if not self._enabled:
            return None

        # Build the RFC 3161 timestamp request
        ts_request = TimestampRequestBuilder().data(data).build()
        request_bytes = ts_request.as_bytes()

        for url in self._tsa_urls:
            token = self._try_tsa(url, request_bytes)
            if token is not None:
                return token

        logger.warning(
            "All TSA servers failed. Chain entry written without RFC 3161 timestamp. "
            "This reduces the evidentiary strength of the audit trail. "
            "TSA servers tried: %s",
            self._tsa_urls,
        )
        return None

    def _try_tsa(self, url: str, request_bytes: bytes) -> TSAToken | None:
        """Attempt a single TSA server. Returns TSAToken or None on failure."""
        try:
            response = httpx.post(
                url,
                content=request_bytes,
                headers={"Content-Type": TSA_CONTENT_TYPE},
                timeout=self._timeout,
                follow_redirects=True,
            )
            response.raise_for_status()

            # Verify the response is parseable
            ts_response = decode_timestamp_response(response.content)
            _ = ts_response  # validation — decode_timestamp_response raises on error

            logger.debug("RFC 3161 timestamp obtained from %s", url)
            return TSAToken(tsa_url=url, token_bytes=response.content)

        except httpx.HTTPStatusError as exc:
            logger.warning(
                "TSA server %s returned HTTP %d: %s",
                url, exc.response.status_code, exc,
            )
        except httpx.RequestError as exc:
            logger.warning("TSA server %s network error: %s", url, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("TSA server %s unexpected error: %s", url, exc)

        return None
