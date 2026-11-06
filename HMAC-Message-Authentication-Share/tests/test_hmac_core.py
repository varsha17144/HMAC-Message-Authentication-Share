"""
tests/test_hmac_core.py — Unit tests for hmac_core.py.

Correctness is anchored to published, independent test vectors (RFC 4231),
so the implementation is checked against the standard, not merely against
itself. The equivalence tests additionally prove that the hand-written
RFC 2104 construction (manual_hmac) matches Python's standard-library hmac.
"""

import unittest

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hmac_core import (
    abbreviate_hash,
    build_replay_data,
    hmac_sha256,
    manual_hmac,
    plaintext_hash,
    sign_message,
    sign_replay_message,
    verify_message,
    verify_message_detailed,
)


class TestManualHmacAgainstRfc4231(unittest.TestCase):
    """RFC 4231 'Test Case' vectors for HMAC-SHA256."""

    def test_rfc4231_test_case_1(self):
        # Key = 20 bytes of 0x0b, data = "Hi There"
        key = "\x0b" * 20
        self.assertEqual(
            manual_hmac(key, "Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        )

    def test_rfc4231_test_case_2(self):
        # Key = "Jefe", data = "what do ya want for nothing?"
        self.assertEqual(
            manual_hmac("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        )

    def test_rfc4231_test_case_3(self):
        # Key = 20 bytes of 0xaa, data = 50 bytes of 0xdd (raw byte values)
        key = b"\xaa" * 20
        data = b"\xdd" * 50
        self.assertEqual(
            manual_hmac(key, data),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        )

    def test_rfc4231_test_case_6(self):
        # Large key (131 bytes of 0xaa) — exercises the "hash long keys" branch
        key = b"\xaa" * 131
        data = b"Test Using Larger Than Block-Size Key - Hash Key First"
        self.assertEqual(
            manual_hmac(key, data),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        )


class TestStdlibHmacMatchesManual(unittest.TestCase):
    """manual_hmac() must agree with Python's hmac module on every input."""

    def test_short_key(self):
        self.assertEqual(manual_hmac("secret", "hello"), hmac_sha256("secret", "hello"))

    def test_long_key(self):
        key = "K" * 200  # longer than the 64-byte block -> triggers key hashing
        self.assertEqual(manual_hmac(key, "message"), hmac_sha256(key, "message"))

    def test_empty_message(self):
        self.assertEqual(manual_hmac("key", ""), hmac_sha256("key", ""))

    def test_unicode_message(self):
        self.assertEqual(
            manual_hmac("k€y", "héllo wörld 你好"),
            hmac_sha256("k€y", "héllo wörld 你好"),
        )


class TestVerifyMessage(unittest.TestCase):
    """Behaviour of the verification path used by the demo."""

    def test_valid_tag_verifies(self):
        tag = hmac_sha256("our-secret", "Pay Alice $100")
        self.assertTrue(verify_message("Pay Alice $100", "our-secret", tag))

    def test_tampered_message_fails(self):
        # The tamper simulation from the demo: change one character, must fail
        tag = hmac_sha256("our-secret", "Pay Alice $100")
        self.assertFalse(verify_message("Pay Alice $900", "our-secret", tag))

    def test_wrong_key_fails(self):
        tag = hmac_sha256("our-secret", "Pay Alice $100")
        self.assertFalse(verify_message("Pay Alice $100", "wrong-key", tag))

    def test_case_and_whitespace_insensitive_tag_input(self):
        # Receiver-side convenience: uppercase / padded tag should still verify
        tag = hmac_sha256("k", "m")
        self.assertTrue(verify_message("m", "k", "  " + tag.upper() + "  "))

    def test_garbage_tag_does_not_crash(self):
        self.assertFalse(verify_message("m", "k", "not-a-real-tag"))

    def test_empty_tag_fails(self):
        # An empty tag must never verify (safety, not just validity)
        self.assertFalse(verify_message("m", "k", ""))

    def test_wrong_length_tag_fails(self):
        # Truncated/extended hex tags (e.g. attacker sends a partial tag)
        tag = hmac_sha256("k", "m")
        self.assertFalse(verify_message("m", "k", tag[:32]))   # 16 bytes
        self.assertFalse(verify_message("m", "k", tag + "ab")) # 33 bytes


class TestSignMessageAndPlaintextHash(unittest.TestCase):
    """sign_message() bundles exactly what the demo UI needs."""

    def test_sign_message_fields(self):
        result = sign_message("hello", "key")
        self.assertEqual(result["message"], "hello")
        self.assertEqual(result["hmac"], hmac_sha256("key", "hello"))
        self.assertEqual(result["sha256"], plaintext_hash("hello"))

    def test_hmac_differs_from_plain_hash(self):
        # Core demo point: with a key, the tag is unlike the bare hash
        result = sign_message("same message", "same key")
        self.assertNotEqual(result["hmac"], result["sha256"])

    def test_avalanche_effect(self):
        # One character change in the key -> completely different tag
        h1 = hmac_sha256("key", "msg")
        h2 = hmac_sha256("keY", "msg")
        self.assertNotEqual(h1, h2)

    def test_bare_hash_is_deterministic_without_key(self):
        # Same message -> same plain hash (this is WHY it's not authentic on its own)
        self.assertEqual(plaintext_hash("msg"), plaintext_hash("msg"))


class TestReplayAndDetailedHelpers(unittest.TestCase):
    """Tests for freshness helper functions, hash abbreviation, and detailed verification."""

    def test_abbreviate_hash_standard(self):
        full_hash = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        abbr = abbreviate_hash(full_hash, 8, 8)
        self.assertEqual(abbr, "b0344c61...2e32cff7")

    def test_abbreviate_hash_short_or_invalid(self):
        self.assertEqual(abbreviate_hash("abcdef"), "abcdef")
        self.assertEqual(abbreviate_hash(""), "")
        self.assertEqual(abbreviate_hash(None), "")

    def test_build_replay_data_canonical_format(self):
        payload = build_replay_data("Pay 100", 1700000000.5, "nonce123")
        self.assertEqual(payload, "1700000000.5:nonce123:Pay 100")

    def test_sign_replay_message(self):
        result = sign_replay_message("Action", "key42", 1700000000, "n1")
        self.assertEqual(result["message"], "Action")
        self.assertEqual(result["timestamp"], 1700000000)
        self.assertEqual(result["nonce"], "n1")
        self.assertEqual(result["authenticated_data"], "1700000000:n1:Action")
        expected_tag = hmac_sha256("key42", "1700000000:n1:Action")
        self.assertEqual(result["hmac"], expected_tag)

    def test_verify_message_detailed_success(self):
        tag = hmac_sha256("my-secret", "important message")
        res = verify_message_detailed("important message", "my-secret", tag)
        self.assertTrue(res["valid"])
        self.assertTrue(res["crypto_valid"])
        self.assertIn("Valid authentication", res["reason"])
        self.assertEqual(res["received_hmac_short"], abbreviate_hash(tag))
        self.assertEqual(res["expected_hmac_short"], abbreviate_hash(tag))

    def test_verify_message_detailed_mismatch(self):
        tag = hmac_sha256("my-secret", "original")
        res = verify_message_detailed("tampered", "my-secret", tag)
        self.assertFalse(res["valid"])
        self.assertFalse(res["crypto_valid"])
        self.assertIn("Verification failed", res["reason"])
        self.assertNotEqual(res["received_hmac_short"], res["expected_hmac_short"])

    def test_verify_message_detailed_malformed_tag(self):
        res = verify_message_detailed("msg", "key", None)
        self.assertFalse(res["valid"])
        self.assertIn("Malformed", res["reason"])


if __name__ == "__main__":
    unittest.main()
