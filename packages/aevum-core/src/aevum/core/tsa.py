# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 Aevum Labs contributors
"""
RFC 3161 Time-Stamping Authority (TSA) client for the Aevum sigchain.

What RFC 3161 is: a standard (RFC 3161 / RFC 5816) for requesting a trusted third-party
timestamp over a hash of data. The TSA signs the timestamp with its own certificate,
providing proof that the data existed before a specific time — independently of the
operator's clock. This is the "notary" in the sigchain: even if the operator's system
time is wrong or spoofed, the TSA timestamp is signed by an external authority.

Why external timestamps matter for regulated workloads:
  HIPAA §164.312(b) — Audit controls: requires accurate time sources for audit log entries.
    A self-asserted system clock is not a trusted time source under HIPAA.
  FDA 21 CFR Part 11 — Electronic records: requires audit trail entries to include accurate
    dates and times from a trusted source.
  The TSA provides the "trusted source" element that operator-controlled system time cannot.

TTC ordering (Timestamp Then COSE, draft-ietf-cose-tsa-tst-header-parameter-08):
  The TST (TimeStampToken) timestamps the canonical payload bytes, not the COSE_Sign1
  receipt. This ordering matters: the timestamp proves the payload existed at this time;
  the COSE receipt then wraps both. Reversing the order would make the timestamp cover
  only the receipt metadata, not the underlying data being timestamped.

Rate-limiting: The Sigstore TSA (~100 req/min) and DigiCert TSA are free but rate-limited.
  In CI and dev mode, the sigchain uses NullBackend or mocked httpx to avoid consuming
  rate-limit quota. Never send real TSA requests from test suites.

Uses rfc3161-client (Trail of Bits) for binary encoding/decoding (pure codec, no network).
Uses httpx for HTTP transport.

Circuit-breaker design: TSA failures never block sigchain writes. An entry written without
a tsa_token is still cryptographically valid (Ed25519+SHA3-256); it simply lacks the
third-party time attestation. The evidentiary strength is reduced but the audit record exists.
"""
from __future__ import annotations

import dataclasses
import logging
import os

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


def _get_tsa_urls() -> list[str]:
    """Return TSA URL list, respecting AEVUM_TSA_URL env-var override.

    If AEVUM_TSA_URL is set, it replaces the default multi-URL list with
    a single entry pointing to the configured TSA. This allows operators to
    route timestamps to a private or on-premises TSA without code changes.
    """
    env_url = os.environ.get("AEVUM_TSA_URL")
    if env_url:
        return [env_url]
    return DEFAULT_TSA_URLS

TSA_TIMEOUT_SECONDS = 10.0
TSA_CONTENT_TYPE = "application/timestamp-query"


@dataclasses.dataclass(frozen=True)
class TSAToken:
    """Result of a successful RFC 3161 timestamp request.

    token_bytes is the raw DER-encoded TimeStampResponse (the TSA's signed token).
    It should be stored alongside the sigchain entry (in the tsa_token field as hex).
    An investigator can decode token_bytes with any RFC 3161 client library to verify
    the timestamp and the TSA certificate chain without trusting the operator.
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
    """Fetches RFC 3161 timestamps from one or more TSA servers.

    Implements the circuit-breaker pattern: every failure mode (HTTP error, network
    timeout, parse error) is caught and logged; timestamp() returns None rather than
    raising. A sigchain entry written with tsa_token=None is cryptographically valid —
    the Ed25519+SHA3-256 integrity is unaffected. Only the external time attestation
    (the "trusted time source" element required by HIPAA §164.312(b) and FDA 21 CFR Part 11)
    is absent.

    Multiple TSA URLs are tried in order; the first successful response wins. This avoids
    a single point of failure when the primary TSA is rate-limited or unavailable.
    """

    def __init__(
        self,
        tsa_urls: list[str] | None = None,
        timeout: float = TSA_TIMEOUT_SECONDS,
        enabled: bool = True,
    ) -> None:
        self._tsa_urls = tsa_urls or _get_tsa_urls()
        self._timeout = timeout
        self._enabled = enabled

    def timestamp(self, data: bytes) -> TSAToken | None:
        """Request an RFC 3161 timestamp over the canonical payload bytes.

        Follows TTC ordering (Timestamp Then COSE): the TST covers the raw payload bytes,
        not any outer wrapper. This proves the payload existed before the timestamp time,
        which is the correct evidentiary claim for audit purposes.

        Circuit-breaker: returns None rather than raising if TSA is disabled or all
        configured TSA servers fail. The caller (sigchain.new_event) logs the failure
        and writes the entry without a timestamp token — the entry is still valid.

        Args:
            data: The canonical payload bytes to timestamp (RFC 8785 JCS form).

        Returns:
            TSAToken with DER-encoded TimeStampResponse on success; None on any failure.
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
