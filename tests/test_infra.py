"""
Revula Test Suite — Infrastructure tests for cache and rate limiter.

Tests: ResultCache (LRU + TTL), RateLimiter, _TokenBucket.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from revula.cache import ResultCache
from revula.rate_limit import RateLimitConfig, RateLimiter, _TokenBucket
from revula.tools import ToolRegistry, text_result

# ---------------------------------------------------------------------------
# ResultCache Tests
# ---------------------------------------------------------------------------


class TestResultCacheBasic:
    """Basic get/put/invalidate/clear operations."""

    def test_put_and_get(self) -> None:
        cache = ResultCache(max_entries=16, ttl_seconds=300)
        data: list[dict[str, Any]] = [{"type": "text", "text": "hello"}]
        cache.put("k1", data)
        assert cache.get("k1") == data

    def test_get_missing_returns_none(self) -> None:
        cache = ResultCache()
        assert cache.get("nonexistent") is None

    def test_put_overwrites_existing(self) -> None:
        cache = ResultCache()
        cache.put("k1", [{"type": "text", "text": "v1"}])
        cache.put("k1", [{"type": "text", "text": "v2"}])
        result = cache.get("k1")
        assert result is not None
        assert result[0]["text"] == "v2"

    def test_invalidate_removes_key(self) -> None:
        cache = ResultCache()
        cache.put("k1", [{"type": "text", "text": "v1"}])
        cache.invalidate("k1")
        assert cache.get("k1") is None

    def test_invalidate_nonexistent_key_no_error(self) -> None:
        cache = ResultCache()
        cache.invalidate("nokey")  # Should not raise

    def test_clear_resets_everything(self) -> None:
        cache = ResultCache()
        cache.put("a", [{"type": "text", "text": "1"}])
        cache.put("b", [{"type": "text", "text": "2"}])
        # Generate some hits/misses
        cache.get("a")
        cache.get("miss")
        cache.clear()
        # Verify cache is empty and counters reset
        stats = cache.stats()
        assert stats["entries"] == 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0


class TestResultCacheTTL:
    """TTL expiry tests using mocked time.monotonic."""

    def test_entry_expires_after_ttl(self) -> None:
        cache = ResultCache(ttl_seconds=10)
        data: list[dict[str, Any]] = [{"type": "text", "text": "expirable"}]
        with patch("revula.cache.time.monotonic", return_value=100.0):
            cache.put("k1", data)
        # Still valid at t=105
        with patch("revula.cache.time.monotonic", return_value=105.0):
            assert cache.get("k1") is not None
        # Expired at t=111
        with patch("revula.cache.time.monotonic", return_value=111.0):
            assert cache.get("k1") is None

    def test_expired_entry_counted_as_miss(self) -> None:
        cache = ResultCache(ttl_seconds=5)
        with patch("revula.cache.time.monotonic", return_value=0.0):
            cache.put("k1", [{"type": "text", "text": "x"}])
        with patch("revula.cache.time.monotonic", return_value=10.0):
            cache.get("k1")
        stats = cache.stats()
        assert stats["misses"] >= 1


class TestResultCacheLRU:
    """LRU eviction when max_entries is exceeded."""

    def test_lru_eviction(self) -> None:
        cache = ResultCache(max_entries=3, ttl_seconds=600)
        cache.put("a", [{"type": "text", "text": "1"}])
        cache.put("b", [{"type": "text", "text": "2"}])
        cache.put("c", [{"type": "text", "text": "3"}])
        # Adding a 4th should evict 'a' (oldest)
        cache.put("d", [{"type": "text", "text": "4"}])
        assert cache.get("a") is None
        assert cache.get("b") is not None
        assert cache.get("d") is not None

    def test_accessing_entry_refreshes_lru_order(self) -> None:
        cache = ResultCache(max_entries=3, ttl_seconds=600)
        cache.put("a", [{"type": "text", "text": "1"}])
        cache.put("b", [{"type": "text", "text": "2"}])
        cache.put("c", [{"type": "text", "text": "3"}])
        # Access 'a' to make it recently used
        cache.get("a")
        # Now add 'd' — should evict 'b' (least recently used)
        cache.put("d", [{"type": "text", "text": "4"}])
        assert cache.get("a") is not None  # refreshed
        assert cache.get("b") is None  # evicted
        assert cache.get("d") is not None


class TestResultCacheStats:
    """Cache statistics tests."""

    def test_stats_initial(self) -> None:
        cache = ResultCache(max_entries=100)
        stats = cache.stats()
        assert stats["entries"] == 0
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate_pct"] == 0
        assert stats["max_entries"] == 100

    def test_stats_counts_hits_and_misses(self) -> None:
        cache = ResultCache()
        cache.put("k1", [{"type": "text", "text": "v"}])
        cache.get("k1")  # hit
        cache.get("k1")  # hit
        cache.get("missing")  # miss
        stats = cache.stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate_pct"] == 66  # 2/3 * 100 = 66

    def test_stats_entries_count(self) -> None:
        cache = ResultCache()
        cache.put("a", [{"type": "text", "text": "1"}])
        cache.put("b", [{"type": "text", "text": "2"}])
        assert cache.stats()["entries"] == 2


class TestResultCacheMakeKey:
    """make_key static method tests."""

    def test_make_key_deterministic(self) -> None:
        key1 = ResultCache.make_key("tool", {"a": 1, "b": 2})
        key2 = ResultCache.make_key("tool", {"b": 2, "a": 1})
        assert key1 == key2

    def test_make_key_strips_dunder_keys(self) -> None:
        key_with = ResultCache.make_key("tool", {"a": 1, "__config__": "x"})
        key_without = ResultCache.make_key("tool", {"a": 1})
        assert key_with == key_without

    def test_make_key_different_tools_differ(self) -> None:
        key1 = ResultCache.make_key("tool_a", {"x": 1})
        key2 = ResultCache.make_key("tool_b", {"x": 1})
        assert key1 != key2

    def test_make_key_format(self) -> None:
        key = ResultCache.make_key("my_tool", {"arg": "val"})
        assert key.startswith("my_tool:")
        # The hash portion is 16 hex chars
        assert len(key.split(":")[1]) == 16


class TestServerCachePolicy:
    """Server-level cache policy: explicit opt-in only."""

    def test_is_cacheable_tool_requires_explicit_opt_in(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import revula.server as server

        registry = ToolRegistry()

        @registry.register(
            name="cache_opt_out",
            description="default non-cacheable",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        )
        async def _non_cacheable_handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            return text_result({"ok": True})

        @registry.register(
            name="cache_opt_in",
            description="explicit cacheable",
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            cacheable=True,
        )
        async def _cacheable_handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            return text_result({"ok": True})

        monkeypatch.setattr(server, "TOOL_REGISTRY", registry)

        assert server._is_cacheable_tool("cache_opt_out") is False
        assert server._is_cacheable_tool("cache_opt_in") is True

    @pytest.mark.asyncio
    async def test_call_tool_caches_only_opt_in(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import revula.server as server

        registry = ToolRegistry()
        calls: dict[str, int] = {"cache": 0, "no_cache": 0}

        schema = {
            "type": "object",
            "properties": {"value": {"type": "integer"}},
            "required": ["value"],
            "additionalProperties": False,
        }

        @registry.register(
            name="cache_opt_in",
            description="cacheable handler",
            input_schema=schema,
            cacheable=True,
        )
        async def _cacheable_handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            calls["cache"] += 1
            return text_result({"count": calls["cache"]})

        @registry.register(
            name="cache_opt_out",
            description="non-cacheable handler",
            input_schema=schema,
            cacheable=False,
        )
        async def _non_cacheable_handler(args: dict[str, Any]) -> list[dict[str, Any]]:
            calls["no_cache"] += 1
            return text_result({"count": calls["no_cache"]})

        class _AllowAllRateLimiter:
            def check(self, _tool_name: str) -> bool:
                return True

        monkeypatch.setattr(server, "TOOL_REGISTRY", registry)
        monkeypatch.setattr(server, "RESULT_CACHE", ResultCache())
        monkeypatch.setattr(server, "RATE_LIMITER", _AllowAllRateLimiter())
        monkeypatch.setattr(server, "SESSION_MANAGER", object())
        monkeypatch.setattr(server, "get_config", lambda: object())

        first_cached = await server.call_tool("cache_opt_in", {"value": 1})
        second_cached = await server.call_tool("cache_opt_in", {"value": 1})
        first_cached_payload = json.loads(first_cached[0].text)
        second_cached_payload = json.loads(second_cached[0].text)

        assert first_cached_payload["count"] == 1
        assert second_cached_payload["count"] == 1
        assert calls["cache"] == 1

        first_non_cached = await server.call_tool("cache_opt_out", {"value": 1})
        second_non_cached = await server.call_tool("cache_opt_out", {"value": 1})
        first_non_cached_payload = json.loads(first_non_cached[0].text)
        second_non_cached_payload = json.loads(second_non_cached[0].text)

        assert first_non_cached_payload["count"] == 1
        assert second_non_cached_payload["count"] == 2
        assert calls["no_cache"] == 2


# ---------------------------------------------------------------------------
# _TokenBucket Tests
# ---------------------------------------------------------------------------


class TestTokenBucket:
    """Token bucket algorithm tests."""

    def test_consume_succeeds_initially(self) -> None:
        bucket = _TokenBucket(rate=1.0, capacity=5)
        assert bucket.consume() is True

    def test_consume_exhausts_capacity(self) -> None:
        bucket = _TokenBucket(rate=1.0, capacity=3)
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False

    def test_refill_over_time(self) -> None:
        bucket = _TokenBucket(rate=10.0, capacity=5)
        # Exhaust all tokens
        for _ in range(5):
            bucket.consume()
        assert bucket.consume() is False
        # Simulate passage of time (enough for 2 tokens at rate=10/s => 0.2s)
        with patch("revula.rate_limit.time.monotonic", return_value=bucket._last_refill + 0.5):
            assert bucket.consume() is True

    def test_refill_does_not_exceed_capacity(self) -> None:
        bucket = _TokenBucket(rate=100.0, capacity=3)
        # Exhaust
        for _ in range(3):
            bucket.consume()
        # Wait a very long time
        with patch("revula.rate_limit.time.monotonic", return_value=bucket._last_refill + 1000.0):
            # Should refill to capacity (3), not more
            assert bucket.consume() is True
            assert bucket.consume() is True
            assert bucket.consume() is True
            assert bucket.consume() is False


# ---------------------------------------------------------------------------
# RateLimiter Tests
# ---------------------------------------------------------------------------


class TestRateLimiter:
    """RateLimiter with RateLimitConfig tests."""

    def test_check_allows_under_limit(self) -> None:
        limiter = RateLimiter(RateLimitConfig(burst_size=10))
        assert limiter.check("test_tool") is True

    def test_check_denies_after_burst_exhausted(self) -> None:
        cfg = RateLimitConfig(burst_size=2, global_rpm=120, per_tool_rpm=30)
        limiter = RateLimiter(cfg)
        assert limiter.check("t") is True
        assert limiter.check("t") is True
        # 3rd call should fail (burst=2, global bucket exhausted)
        assert limiter.check("t") is False

    def test_disabled_bypasses_check(self) -> None:
        cfg = RateLimitConfig(enabled=False, burst_size=1)
        limiter = RateLimiter(cfg)
        # Even after many calls, should always succeed when disabled
        for _ in range(100):
            assert limiter.check("tool") is True

    def test_stats_reports_correctly(self) -> None:
        cfg = RateLimitConfig(burst_size=5)
        limiter = RateLimiter(cfg)
        limiter.check("t1")
        limiter.check("t2")
        stats = limiter.stats()
        assert stats["enabled"] is True
        assert stats["allowed"] == 2
        assert stats["denied"] == 0
        assert stats["active_tool_buckets"] == 2

    def test_per_tool_buckets_isolated(self) -> None:
        cfg = RateLimitConfig(burst_size=20, per_tool_rpm=30)
        limiter = RateLimiter(cfg)
        limiter.check("tool_a")
        limiter.check("tool_b")
        stats = limiter.stats()
        assert stats["active_tool_buckets"] == 2

    def test_stats_counts_denied(self) -> None:
        cfg = RateLimitConfig(burst_size=1)
        limiter = RateLimiter(cfg)
        limiter.check("t")  # allowed
        limiter.check("t")  # denied (global burst=1)
        stats = limiter.stats()
        assert stats["denied"] >= 1
