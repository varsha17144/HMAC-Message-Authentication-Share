"""
replay_defense.py — In-memory nonce cache and freshness validator for replay protection.

ACADEMIC DEMONSTRATION NOTICE:
This module implements receiver-side replay attack protection for a local classroom
and viva demonstration. It uses an in-memory nonce cache with sliding timestamp tolerance.

LIMITATIONS & PRODUCTION REQUIREMENTS:
  1. Not Persistent: All consumed nonces are kept in memory and will be lost if
     the server restarts.
  2. Not Shared / Distributed: This cache resides within a single process. In a
     production environment with multiple server workers or load-balanced instances,
     a durable, distributed, synchronized key-value store (e.g., Redis cluster using
     atomic SETNX with a Time-To-Live matching the timestamp window) is required.
  3. Clock Synchronization: Timestamp freshness assumes receiver and sender system
     clocks are synchronized via NTP (Network Time Protocol).
  4. Scope: This implementation demonstrates core replay attack defense principles
     and is NOT intended for production deployment without durable coordination.
"""

import threading
import time
from typing import Dict, Tuple

# Tolerance window in seconds: allows for network transit and clock skew.
TIMESTAMP_TOLERANCE_SECONDS = 120.0  # 2 minutes past tolerance
FUTURE_TOLERANCE_SECONDS = 15.0      # 15 seconds allowable future clock skew


class NonceCache:
    """Thread-safe in-memory cache for message nonces with sliding expiration.

    Guarantees atomic check-and-consume behavior to prevent race conditions during
    concurrent requests.
    """

    def __init__(
        self,
        tolerance: float = TIMESTAMP_TOLERANCE_SECONDS,
        future_tolerance: float = FUTURE_TOLERANCE_SECONDS,
    ):
        self.tolerance = float(tolerance)
        self.future_tolerance = float(future_tolerance)
        self._lock = threading.Lock()
        # Maps nonce -> recorded_timestamp
        self._cache: Dict[str, float] = {}

    def check_and_consume(
        self,
        nonce: str,
        msg_time: "float | int | str",
        current_time: "float | None" = None,
    ) -> Tuple[bool, str]:
        """Atomically validate timestamp freshness and consume the nonce.

        Returns (is_valid, reason_code).
        reason_code values:
          - "fresh": valid timestamp and nonce newly consumed.
          - "empty_nonce": nonce was empty, non-string, or whitespace.
          - "invalid_timestamp": timestamp could not be parsed as a float.
          - "expired_timestamp": timestamp is older than allowable tolerance window.
          - "future_timestamp": timestamp is in the future beyond acceptable drift.
          - "reused_nonce": nonce was already seen within the active window.
        """
        if not isinstance(nonce, str) or not nonce.strip():
            return False, "empty_nonce"

        clean_nonce = nonce.strip()
        now = time.time() if current_time is None else float(current_time)

        try:
            ts = float(msg_time)
        except (ValueError, TypeError):
            return False, "invalid_timestamp"

        # Check timestamp bounds against tolerance
        if ts < now - self.tolerance:
            return False, "expired_timestamp"
        if ts > now + self.future_tolerance:
            return False, "future_timestamp"

        with self._lock:
            # Check if nonce was already consumed (replay detected)
            if clean_nonce in self._cache:
                return False, "reused_nonce"

            # Prune expired entries to maintain bounded memory usage
            cutoff = now - self.tolerance
            expired_keys = [k for k, v in self._cache.items() if v < cutoff]
            for k in expired_keys:
                del self._cache[k]

            # Record this nonce atomically
            self._cache[clean_nonce] = now
            return True, "fresh"

    def is_cached(self, nonce: str) -> bool:
        """Check if a nonce currently exists in cache without consuming."""
        with self._lock:
            return nonce.strip() in self._cache

    def clear(self) -> None:
        """Clear the cache (for testing and demo resets)."""
        with self._lock:
            self._cache.clear()

    def count(self) -> int:
        """Return the number of currently tracked nonces."""
        with self._lock:
            return len(self._cache)


# Global default instance for the Flask application
default_nonce_cache = NonceCache()
