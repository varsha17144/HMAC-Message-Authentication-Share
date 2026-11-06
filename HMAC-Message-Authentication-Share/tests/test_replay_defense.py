"""
tests/test_replay_defense.py — Unit tests for replay_defense.py.

Verifies thread-safe nonce tracking, sliding timestamp expiration, and detection
of reused nonces and clock drift.
"""

import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from replay_defense import NonceCache, TIMESTAMP_TOLERANCE_SECONDS


class TestNonceCache(unittest.TestCase):
    def setUp(self):
        self.cache = NonceCache(tolerance=60.0, future_tolerance=10.0)

    def test_fresh_nonce_is_accepted(self):
        now = time.time()
        ok, reason = self.cache.check_and_consume("nonce-1", now, current_time=now)
        self.assertTrue(ok)
        self.assertEqual(reason, "fresh")
        self.assertTrue(self.cache.is_cached("nonce-1"))

    def test_reused_nonce_is_rejected(self):
        now = time.time()
        ok1, reason1 = self.cache.check_and_consume("nonce-dup", now, current_time=now)
        self.assertTrue(ok1)
        self.assertEqual(reason1, "fresh")

        # Second attempt with same nonce
        ok2, reason2 = self.cache.check_and_consume("nonce-dup", now, current_time=now)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "reused_nonce")

    def test_expired_timestamp_is_rejected(self):
        now = time.time()
        expired_time = now - 65.0  # Outside the 60.0s tolerance
        ok, reason = self.cache.check_and_consume("nonce-old", expired_time, current_time=now)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired_timestamp")
        self.assertFalse(self.cache.is_cached("nonce-old"))

    def test_future_timestamp_beyond_tolerance_is_rejected(self):
        now = time.time()
        future_time = now + 15.0  # Outside the 10.0s future tolerance
        ok, reason = self.cache.check_and_consume("nonce-future", future_time, current_time=now)
        self.assertFalse(ok)
        self.assertEqual(reason, "future_timestamp")

    def test_future_timestamp_within_tolerance_is_accepted(self):
        now = time.time()
        slight_future = now + 5.0  # Within the 10.0s future tolerance
        ok, reason = self.cache.check_and_consume("nonce-slight-future", slight_future, current_time=now)
        self.assertTrue(ok)
        self.assertEqual(reason, "fresh")

    def test_empty_or_invalid_nonce_rejected(self):
        now = time.time()
        for bad_nonce in ("", "   ", None, 123):
            ok, reason = self.cache.check_and_consume(bad_nonce, now, current_time=now)
            self.assertFalse(ok)
            self.assertEqual(reason, "empty_nonce")

    def test_invalid_timestamp_rejected(self):
        now = time.time()
        for bad_ts in ("not-a-number", None, []):
            ok, reason = self.cache.check_and_consume("nonce-ts", bad_ts, current_time=now)
            self.assertFalse(ok)
            self.assertEqual(reason, "invalid_timestamp")

    def test_cache_clear(self):
        now = time.time()
        self.cache.check_and_consume("nonce-a", now, current_time=now)
        self.assertEqual(self.cache.count(), 1)
        self.cache.clear()
        self.assertEqual(self.cache.count(), 0)
        self.assertFalse(self.cache.is_cached("nonce-a"))

    def test_pruning_removes_expired_nonces(self):
        t0 = 1000.0
        # Insert nonce at t0
        self.cache.check_and_consume("nonce-old", t0, current_time=t0)
        self.assertEqual(self.cache.count(), 1)

        # Advance current time past tolerance (tolerance is 60s)
        t1 = t0 + 70.0
        # Consuming a new nonce at t1 triggers pruning of nonces older than t1 - 60 (i.e. older than 1010.0)
        self.cache.check_and_consume("nonce-new", t1, current_time=t1)
        self.assertFalse(self.cache.is_cached("nonce-old"))
        self.assertTrue(self.cache.is_cached("nonce-new"))

    def test_concurrent_consumption_thread_safety(self):
        # 20 threads attempting to consume the SAME nonce simultaneously
        # Exactly one must succeed with 'fresh', the other 19 must fail with 'reused_nonce'
        now = time.time()
        target_nonce = "concurrent-race-nonce"
        results = []

        def worker():
            return self.cache.check_and_consume(target_nonce, now, current_time=now)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(20)]
            for f in futures:
                results.append(f.result())

        successes = [r for r in results if r[0] is True]
        reused = [r for r in results if r[1] == "reused_nonce"]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(reused), 19)


if __name__ == "__main__":
    unittest.main()
