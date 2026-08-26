"""
Per-client rate limiting for the endpoints that call out to NVD and OSV.

API authentication is off by default, and `/analyze`, `/generate_identifier`
and component creation all reach public vulnerability databases on the caller's
behalf. Left unbounded they let anyone who can reach the port burn this
deployment's NVD budget — which, because NVD answers an over-budget client with
403 rather than an error, degrades the nightly refresh into silently returning
no vulnerabilities.

The limiter is an in-process sliding window, which is exactly as far as it goes:
with several uvicorn workers or replicas each process keeps its own counter and
the effective limit is N times the configured one. Put the limit on the reverse
proxy if you need a cluster-wide budget.
"""

import logging
import os
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, Response

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning(f"{name} is not an integer ({raw!r}) — using {default}")
        return default


# Requests per minute per client for the external-lookup endpoints.
# Set to 0 to disable. The default is generous for interactive use and still
# well under what it takes to exhaust an NVD budget.
RATE_LIMIT = _int_env("OSS_MONITOR_RATE_LIMIT", 30)

# Number of trusted reverse-proxy hops. Without this the limiter must not read
# X-Forwarded-For at all: the header is client-controlled, so trusting it on a
# directly-exposed service lets anyone reset their own counter per request.
TRUSTED_PROXY_COUNT = _int_env("TRUSTED_PROXY_COUNT", 0)

# bucket -> client -> timestamps of requests inside the window
_hits: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))


def reset() -> None:
    """Drop all counters. For tests."""
    _hits.clear()


def client_key(request: Request) -> str:
    """
    Identify the caller.

    With TRUSTED_PROXY_COUNT set, the real client is that many hops from the
    right of X-Forwarded-For — counting from the right is what makes the value
    unspoofable, since a client can prepend entries but not remove the ones the
    proxies append.
    """
    if TRUSTED_PROXY_COUNT > 0:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            if len(hops) >= TRUSTED_PROXY_COUNT:
                return hops[-TRUSTED_PROXY_COUNT]

    return request.client.host if request.client else "unknown"


def _check(bucket: str, client: str, limit: int) -> tuple[int, int]:
    """
    Record a hit and return `(remaining, reset_in_seconds)`.

    Raises HTTPException(429) when the window is full.
    """
    now = time.monotonic()
    window = _hits[bucket][client]

    cutoff = now - WINDOW_SECONDS
    while window and window[0] <= cutoff:
        window.popleft()

    if len(window) >= limit:
        retry_after = max(1, int(window[0] + WINDOW_SECONDS - now) + 1)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {limit} requests per minute. "
                   f"Retry in {retry_after}s.",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(retry_after),
            },
        )

    window.append(now)
    remaining = limit - len(window)
    reset_in = int(window[0] + WINDOW_SECONDS - now) + 1 if window else WINDOW_SECONDS
    return remaining, reset_in


def rate_limit(bucket: str, limit: int | None = None):
    """
    Build a FastAPI dependency limiting `bucket` to `limit` requests/minute.

    Endpoints sharing a bucket share a budget, so a caller cannot dodge the
    limit by alternating between two equally expensive endpoints.
    """
    async def dependency(request: Request, response: Response) -> None:
        effective = RATE_LIMIT if limit is None else limit
        if effective <= 0:
            return  # disabled

        remaining, reset_in = _check(bucket, client_key(request), effective)
        response.headers["X-RateLimit-Limit"] = str(effective)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_in)

    return dependency
