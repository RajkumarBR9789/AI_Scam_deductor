"""
Redis-backed scan result cache.

Keys: scan_cache:<sha256(scan_type + input_text)>
Values: JSON-serialised scan response dicts
TTL: configurable via settings.SCAN_CACHE_TTL_SECONDS (default 1 hour)

Falls back silently when Redis is unavailable — scans still work, just uncached.
"""

import hashlib
import json
import logging
from typing import Any

import redis

from config import settings

logger = logging.getLogger(__name__)

_PREFIX = "scan_cache:"

try:
    _pool = redis.ConnectionPool.from_url(settings.REDIS_URL, decode_responses=True)
    _client: redis.Redis | None = redis.Redis(connection_pool=_pool)
    _client.ping()
    logger.info("Redis cache connected at %s", settings.REDIS_URL)
except Exception:
    _client = None
    logger.warning("Redis unavailable — scan caching disabled")


def _cache_key(scan_type: str, input_text: str) -> str:
    raw = f"{scan_type}:{input_text.strip().lower()}"
    return _PREFIX + hashlib.sha256(raw.encode()).hexdigest()


def get_cached_scan(scan_type: str, input_text: str) -> dict[str, Any] | None:
    """Return cached scan result dict or None."""
    if _client is None:
        return None
    try:
        data = _client.get(_cache_key(scan_type, input_text))
        if data:
            logger.debug("Cache HIT for %s: %.40s", scan_type, input_text)
            return json.loads(data)
    except Exception:
        pass
    return None


def set_cached_scan(scan_type: str, input_text: str, result: dict[str, Any]) -> None:
    """Store scan result in cache with TTL."""
    if _client is None:
        return
    try:
        _client.setex(
            _cache_key(scan_type, input_text),
            settings.SCAN_CACHE_TTL_SECONDS,
            json.dumps(result, default=str),
        )
        logger.debug("Cache SET for %s: %.40s", scan_type, input_text)
    except Exception:
        pass
