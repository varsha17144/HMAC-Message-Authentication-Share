"""
tests/test_api.py — Tests for the Flask endpoints in app.py.

Uses Flask's built-in test client, so the API is exercised end-to-end
(routing, JSON parsing, validation, status codes) without starting a server.
"""

import time
import unittest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app
from hmac_core import build_replay_data, hmac_sha256
from replay_defense import default_nonce_cache


class TestSignEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_sign_returns_hmac_and_sha256(self):
        res = self.client.post("/api/sign", json={"message": "hello", "key": "secret"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["message"], "hello")
        self.assertEqual(data["hmac"], hmac_sha256("secret", "hello"))
        self.assertIn("sha256", data)

    def test_sign_rejects_non_json_body(self):
        res = self.client.post("/api/sign", data="not json", content_type="text/plain")
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_sign_rejects_missing_key(self):
        res = self.client.post("/api/sign", json={"message": "hello"})
        self.assertEqual(res.status_code, 400)

    def test_sign_rejects_empty_message(self):
        res = self.client.post("/api/sign", json={"message": "", "key": "k"})
        self.assertEqual(res.status_code, 400)

    def test_sign_rejects_non_string_values(self):
        res = self.client.post("/api/sign", json={"message": 123, "key": "k"})
        self.assertEqual(res.status_code, 400)


class TestVerifyEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_verify_accepts_correct_tag(self):
        tag = hmac_sha256("secret", "Pay Alice $100")
        res = self.client.post(
            "/api/verify",
            json={"message": "Pay Alice $100", "key": "secret", "hmac": tag},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {"valid": True})

    def test_verify_rejects_tampered_message(self):
        # The core demo scenario: attacker flips $100 -> $900 in transit
        tag = hmac_sha256("secret", "Pay Alice $100")
        res = self.client.post(
            "/api/verify",
            json={"message": "Pay Alice $900", "key": "secret", "hmac": tag},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {"valid": False})

    def test_verify_rejects_wrong_key(self):
        tag = hmac_sha256("secret", "m")
        res = self.client.post(
            "/api/verify", json={"message": "m", "key": "other", "hmac": tag}
        )
        self.assertEqual(res.get_json(), {"valid": False})

    def test_verify_missing_fields_return_400(self):
        res = self.client.post("/api/verify", json={"message": "m", "key": "k"})
        self.assertEqual(res.status_code, 400)

    def test_verify_empty_hmac_returns_400(self):
        # Empty tag is invalid client input -> rejected before any comparison
        res = self.client.post(
            "/api/verify", json={"message": "m", "key": "k", "hmac": ""}
        )
        self.assertEqual(res.status_code, 400)

    def test_verify_malformed_hmac_returns_invalid(self):
        # Well-formed request but nonsense / wrong-length tag -> 200, valid: false
        for bad_tag in ("zzzz", "abcd1234", "a" * 63):
            res = self.client.post(
                "/api/verify", json={"message": "m", "key": "k", "hmac": bad_tag}
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.get_json(), {"valid": False})


class TestIndexRoute(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_index_returns_200_and_renders_html(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Interactive Message Integrity", res.data)
        self.assertIn(b"Replay Attack Simulation", res.data)


class TestErrorHandling(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_unknown_endpoint_is_json_404(self):
        res = self.client.get("/api/nope")
        self.assertEqual(res.status_code, 404)
        self.assertIn("error", res.get_json())

    def test_get_on_sign_is_json_405(self):
        res = self.client.get("/api/sign")
        self.assertEqual(res.status_code, 405)
        self.assertIn("error", res.get_json())


class TestVerifyDetailedEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_verify_detailed_accepts_valid(self):
        tag = hmac_sha256("k1", "secure-command")
        res = self.client.post(
            "/api/verify",
            json={"message": "secure-command", "key": "k1", "hmac": tag, "details": True},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["valid"])
        self.assertTrue(data["crypto_valid"])
        self.assertIn("Valid authentication", data["reason"])
        self.assertIn("received_hmac_short", data)
        self.assertIn("expected_hmac_short", data)

    def test_verify_detailed_rejects_tampered(self):
        tag = hmac_sha256("k1", "secure-command")
        res = self.client.post(
            "/api/verify",
            json={"message": "tampered-command", "key": "k1", "hmac": tag, "details": True},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["valid"])
        self.assertFalse(data["crypto_valid"])
        self.assertIn("Verification failed", data["reason"])


class TestReplayEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        default_nonce_cache.clear()

    def tearDown(self):
        default_nonce_cache.clear()

    def test_replay_sign_auto_generates_nonce_and_timestamp(self):
        res = self.client.post(
            "/api/replay/sign",
            json={"message": "Debit 100", "key": "secret-key"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["message"], "Debit 100")
        self.assertIn("timestamp", data)
        self.assertIn("nonce", data)
        self.assertIn("authenticated_data", data)
        self.assertIn("hmac", data)
        # Verify authenticated_data matches canonical format
        expected_payload = build_replay_data("Debit 100", data["timestamp"], data["nonce"])
        self.assertEqual(data["authenticated_data"], expected_payload)
        self.assertEqual(data["hmac"], hmac_sha256("secret-key", expected_payload))

    def test_replay_sign_with_custom_nonce_and_timestamp(self):
        res = self.client.post(
            "/api/replay/sign",
            json={
                "message": "Transfer 50",
                "key": "key123",
                "nonce": "fixed-nonce-1",
                "timestamp": 1700000000.0,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["nonce"], "fixed-nonce-1")
        self.assertEqual(data["timestamp"], 1700000000.0)

    def test_replay_sign_validation(self):
        # Missing key
        res1 = self.client.post("/api/replay/sign", json={"message": "hi"})
        self.assertEqual(res1.status_code, 400)
        # Empty message
        res2 = self.client.post("/api/replay/sign", json={"message": "", "key": "k"})
        self.assertEqual(res2.status_code, 400)
        # Non-JSON
        res3 = self.client.post("/api/replay/sign", data="raw", content_type="text/plain")
        self.assertEqual(res3.status_code, 400)

    def test_replay_case_1_fresh_valid_accepted(self):
        # Case 1: Fresh valid message is accepted
        now = time.time()
        nonce = "fresh-nonce-101"
        msg = "Authorize Transfer"
        key = "shared-bank-key"
        payload = build_replay_data(msg, now, nonce)
        tag = hmac_sha256(key, payload)

        res = self.client.post(
            "/api/replay/verify",
            json={
                "message": msg,
                "key": key,
                "timestamp": now,
                "nonce": nonce,
                "hmac": tag,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["valid"])
        self.assertTrue(data["crypto_valid"])
        self.assertTrue(data["freshness_valid"])
        self.assertEqual(data["reason_code"], "authenticated_fresh")

    def test_replay_case_2_modified_message_rejected(self):
        # Case 2: Modified message is rejected (crypto mismatch)
        now = time.time()
        nonce = "tamper-nonce-202"
        key = "shared-bank-key"
        payload = build_replay_data("Original Text", now, nonce)
        tag = hmac_sha256(key, payload)

        # Attacker modifies message in transit, preserves original tag
        res = self.client.post(
            "/api/replay/verify",
            json={
                "message": "Original Text [TAMPERED]",
                "key": key,
                "timestamp": now,
                "nonce": nonce,
                "hmac": tag,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["valid"])
        self.assertFalse(data["crypto_valid"])
        self.assertEqual(data["reason_code"], "crypto_mismatch")

    def test_replay_case_2_tampered_timestamp_or_nonce_rejected(self):
        # Case 2 variant: Attacker modifies timestamp or nonce in transit
        now = time.time()
        nonce = "tamper-nonce-303"
        key = "shared-bank-key"
        payload = build_replay_data("Cmd", now, nonce)
        tag = hmac_sha256(key, payload)

        # Attacker tampers with nonce to bypass freshness, but doesn't have secret key
        res = self.client.post(
            "/api/replay/verify",
            json={
                "message": "Cmd",
                "key": key,
                "timestamp": now,
                "nonce": "tamper-nonce-303-altered",
                "hmac": tag,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["valid"])
        self.assertFalse(data["crypto_valid"])
        self.assertEqual(data["reason_code"], "crypto_mismatch")

    def test_replay_case_3_replayed_nonce_rejected(self):
        # Case 3: Previously accepted message replayed with same nonce is rejected
        now = time.time()
        nonce = "replay-target-nonce-404"
        msg = "Single-Use Command"
        key = "shared-bank-key"
        payload = build_replay_data(msg, now, nonce)
        tag = hmac_sha256(key, payload)

        req_body = {
            "message": msg,
            "key": key,
            "timestamp": now,
            "nonce": nonce,
            "hmac": tag,
        }

        # First presentation: accepted
        res1 = self.client.post("/api/replay/verify", json=req_body)
        self.assertEqual(res1.status_code, 200)
        self.assertTrue(res1.get_json()["valid"])

        # Second presentation (Replay Attack): rejected!
        res2 = self.client.post("/api/replay/verify", json=req_body)
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertFalse(data2["valid"])
        self.assertTrue(data2["crypto_valid"])     # Crypto HMAC matches!
        self.assertFalse(data2["freshness_valid"]) # But freshness check failed!
        self.assertEqual(data2["reason_code"], "reused_nonce")
        self.assertIn("Replay attack detected", data2["reason"])

    def test_replay_expired_timestamp_rejected(self):
        now = time.time()
        expired_ts = now - 300.0  # 5 minutes ago (outside 120s tolerance)
        nonce = "expired-ts-nonce"
        key = "shared-bank-key"
        payload = build_replay_data("Msg", expired_ts, nonce)
        tag = hmac_sha256(key, payload)

        res = self.client.post(
            "/api/replay/verify",
            json={
                "message": "Msg",
                "key": key,
                "timestamp": expired_ts,
                "nonce": nonce,
                "hmac": tag,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["valid"])
        self.assertTrue(data["crypto_valid"])
        self.assertFalse(data["freshness_valid"])
        self.assertEqual(data["reason_code"], "expired_timestamp")

    def test_replay_wrong_key_rejected(self):
        now = time.time()
        nonce = "wrong-key-nonce"
        payload = build_replay_data("Msg", now, nonce)
        tag = hmac_sha256("actual-key", payload)

        res = self.client.post(
            "/api/replay/verify",
            json={
                "message": "Msg",
                "key": "wrong-key",
                "timestamp": now,
                "nonce": nonce,
                "hmac": tag,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["valid"])
        self.assertFalse(data["crypto_valid"])

    def test_replay_verify_validation_errors(self):
        # Missing timestamp
        res1 = self.client.post(
            "/api/replay/verify",
            json={"message": "m", "key": "k", "hmac": "h", "nonce": "n"},
        )
        self.assertEqual(res1.status_code, 400)

        # Empty nonce
        res2 = self.client.post(
            "/api/replay/verify",
            json={"message": "m", "key": "k", "hmac": "h", "nonce": "", "timestamp": 123},
        )
        self.assertEqual(res2.status_code, 400)

        # Non-numeric timestamp
        res3 = self.client.post(
            "/api/replay/verify",
            json={"message": "m", "key": "k", "hmac": "h", "nonce": "n", "timestamp": "invalid"},
        )
        self.assertEqual(res3.status_code, 400)

    def test_replay_reset_endpoint(self):
        now = time.time()
        default_nonce_cache.check_and_consume("to-be-cleared", now, current_time=now)
        self.assertEqual(default_nonce_cache.count(), 1)

        res = self.client.post("/api/replay/reset", json={})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "cleared")
        self.assertEqual(default_nonce_cache.count(), 0)

    def test_simulate_stale_endpoint_generates_valid_hmac_and_fails_freshness(self):
        # 1. Ask backend to generate an educational stale-packet fixture
        res = self.client.post(
            "/api/replay/simulate-stale",
            json={"message": "Stale Action", "key": "k-secret", "age_seconds": 200.0},
        )
        self.assertEqual(res.status_code, 200)
        stale_packet = res.get_json()
        self.assertTrue(stale_packet["simulated_stale"])
        self.assertEqual(stale_packet["message"], "Stale Action")
        # Verify that the HMAC tag is mathematically genuine for the stale timestamp
        expected_tag = hmac_sha256(
            "k-secret",
            build_replay_data("Stale Action", stale_packet["timestamp"], stale_packet["nonce"]),
        )
        self.assertEqual(stale_packet["hmac"], expected_tag)

        # 2. Submit this genuine stale packet to normal verification endpoint
        verify_res = self.client.post("/api/replay/verify", json={
            "message": stale_packet["message"],
            "key": "k-secret",
            "timestamp": stale_packet["timestamp"],
            "nonce": stale_packet["nonce"],
            "hmac": stale_packet["hmac"],
        })
        self.assertEqual(verify_res.status_code, 200)
        v_data = verify_res.get_json()
        self.assertFalse(v_data["valid"])
        self.assertTrue(v_data["crypto_valid"])  # Crypto passes!
        self.assertFalse(v_data["freshness_valid"]) # Freshness fails!
        self.assertEqual(v_data["code"], "TIMESTAMP_EXPIRED")
        self.assertEqual(v_data["reason_code"], "expired_timestamp")

    def test_altered_timestamp_with_invalid_hmac_rejected_as_crypto_mismatch(self):
        now = time.time()
        key = "sec"
        nonce = "ts-tamper-nonce"
        payload = build_replay_data("Msg", now, nonce)
        tag = hmac_sha256(key, payload)

        # Attacker alters timestamp from 'now' to 'now - 300' without updating HMAC tag
        res = self.client.post("/api/replay/verify", json={
            "message": "Msg",
            "key": key,
            "timestamp": now - 300.0,
            "nonce": nonce,
            "hmac": tag,
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        # Must fail on crypto mismatch, NOT on timestamp expired, because HMAC covers timestamp!
        self.assertFalse(data["valid"])
        self.assertFalse(data["crypto_valid"])
        self.assertEqual(data["code"], "CRYPTO_MISMATCH")

    def test_nonce_cache_poisoning_prevention_on_crypto_failure(self):
        # Attacker tries to poison the nonce cache with invalid packet
        now = time.time()
        poison_nonce = "poison-target-1"
        key = "valid-key"

        # Tampered message / invalid tag
        res1 = self.client.post("/api/replay/verify", json={
            "message": "Tampered",
            "key": key,
            "timestamp": now,
            "nonce": poison_nonce,
            "hmac": "invalid-hmac-tag-12345",
        })
        self.assertEqual(res1.status_code, 200)
        self.assertFalse(res1.get_json()["valid"])
        # Verify the nonce was NOT consumed in the cache
        self.assertFalse(default_nonce_cache.is_cached(poison_nonce))

        # Legitimate sender subsequently uses this nonce with valid HMAC -> must succeed!
        valid_payload = build_replay_data("Legitimate", now, poison_nonce)
        valid_tag = hmac_sha256(key, valid_payload)
        res2 = self.client.post("/api/replay/verify", json={
            "message": "Legitimate",
            "key": key,
            "timestamp": now,
            "nonce": poison_nonce,
            "hmac": valid_tag,
        })
        self.assertEqual(res2.status_code, 200)
        self.assertTrue(res2.get_json()["valid"])
        self.assertTrue(default_nonce_cache.is_cached(poison_nonce))

    def test_nonce_cache_poisoning_prevention_on_expired_timestamp(self):
        now = time.time()
        stale_nonce = "stale-target-nonce"
        expired_ts = now - 500.0
        key = "k"
        payload = build_replay_data("Msg", expired_ts, stale_nonce)
        tag = hmac_sha256(key, payload)

        res = self.client.post("/api/replay/verify", json={
            "message": "Msg",
            "key": key,
            "timestamp": expired_ts,
            "nonce": stale_nonce,
            "hmac": tag,
        })
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.get_json()["valid"])
        # Nonce must not be stored
        self.assertFalse(default_nonce_cache.is_cached(stale_nonce))

    def test_concurrent_duplicate_delivery_race(self):
        from concurrent.futures import ThreadPoolExecutor

        now = time.time()
        key = "concurrent-key"
        nonce = "race-nonce-xyz"
        msg = "Single Execution Action"
        payload = build_replay_data(msg, now, nonce)
        tag = hmac_sha256(key, payload)

        req_body = {
            "message": msg,
            "key": key,
            "timestamp": now,
            "nonce": nonce,
            "hmac": tag,
        }

        # Send 10 simultaneous requests
        def send_request():
            return self.client.post("/api/replay/verify", json=req_body)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_request) for _ in range(10)]
            responses = [f.result() for f in futures]

        # Exactly 1 accepted, 9 rejected
        successes = [r for r in responses if r.get_json().get("valid") is True]
        rejections = [r for r in responses if r.get_json().get("valid") is False]

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(rejections), 9)
        for r in rejections:
            self.assertEqual(r.get_json().get("code"), "REUSED_NONCE")


if __name__ == "__main__":
    unittest.main()
