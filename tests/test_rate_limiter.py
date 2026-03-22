"""Tests for the RateLimiter."""

from __future__ import annotations

import time

from presidio_requests import RateLimiter


class TestRateLimiter:
    def test_first_request_no_wait(self):
        rl = RateLimiter(max_requests_per_second=10.0)
        waited = rl.wait_if_needed("https://example.com/")
        assert waited == 0.0

    def test_rapid_requests_throttled(self):
        rl = RateLimiter(max_requests_per_second=2.0)
        rl.wait_if_needed("https://example.com/a")
        rl.record_success("https://example.com/a")

        start = time.monotonic()
        rl.wait_if_needed("https://example.com/b")
        elapsed = time.monotonic() - start
        assert elapsed >= 0.3  # min_interval = 0.5s, some tolerance

    def test_different_hosts_independent(self):
        rl = RateLimiter(max_requests_per_second=2.0)
        rl.wait_if_needed("https://host-a.com/")
        rl.record_success("https://host-a.com/")

        waited = rl.wait_if_needed("https://host-b.com/")
        assert waited == 0.0

    def test_backoff_on_error(self):
        rl = RateLimiter(max_requests_per_second=10.0, backoff_factor=1.0)
        rl.record_error("https://example.com/")
        state = rl._get_host_state("example.com")
        assert state.consecutive_errors == 1
        assert state.current_interval > rl.min_interval

    def test_backoff_resets_on_success(self):
        rl = RateLimiter(max_requests_per_second=10.0)
        rl.record_error("https://example.com/")
        rl.record_error("https://example.com/")
        rl.record_success("https://example.com/")
        state = rl._get_host_state("example.com")
        assert state.consecutive_errors == 0
        assert state.current_interval == rl.min_interval

    def test_max_backoff_cap(self):
        rl = RateLimiter(max_requests_per_second=10.0, max_backoff=5.0, backoff_factor=1.0)
        for _ in range(20):
            rl.record_error("https://example.com/")
        state = rl._get_host_state("example.com")
        assert state.current_interval <= 5.0

    def test_reset_clears_all_hosts(self):
        rl = RateLimiter()
        rl.wait_if_needed("https://a.com/")
        rl.wait_if_needed("https://b.com/")
        rl.reset()
        assert len(rl._hosts) == 0

    def test_unknown_host_fallback(self):
        rl = RateLimiter()
        waited = rl.wait_if_needed("not-a-url")
        assert waited == 0.0
