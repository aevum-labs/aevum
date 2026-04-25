"""
OTel instrumentation for complications.

Wraps Complication.run() with a span automatically.
Emits cost telemetry aligned with FOCUS 1.3 (Phase 6 completes this).
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


def instrument(complication_name: str) -> Callable:  # type: ignore[type-arg]
    """
    Decorator: wraps an async run() with an OTel span.
    Safe no-op if opentelemetry is not configured.

    Usage:
        class MyComp(Complication):
            @instrument("my-comp")
            async def run(self, ctx, payload):
                ...
    """
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not _OTEL_AVAILABLE:
                return await fn(*args, **kwargs)
            tracer = trace.get_tracer("aevum.sdk")
            with tracer.start_as_current_span(
                f"complication.{complication_name}.run"
            ) as span:
                start = time.perf_counter()
                try:
                    result = await fn(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
                finally:
                    duration_ms = int((time.perf_counter() - start) * 1000)
                    span.set_attribute("complication.duration_ms", duration_ms)
        return wrapper
    return decorator
