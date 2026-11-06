"""
hmac_core.py — Core HMAC logic for the "HMAC-Based Message Authentication System".

HMAC (Keyed-Hash Message Authentication Code) is defined in RFC 2104.

Construction:
    HMAC(K, m) = H( (K' ^ opad) || H( (K' ^ ipad) || m ) )
where:
    K  = the secret key
    K' = key padded/derived to the block size of the hash (64 bytes for SHA-256)
    m  = the message
    H  = the underlying hash function (here: SHA-256)
    ipad (inner pad) = 0x36 repeated to block size
    opad (outer pad) = 0x5c repeated to block size
    || denotes concatenation, ^ denotes XOR

This module provides:
    1. plaintext_hash()      — bare SHA-256 (shown in the demo to contrast with HMAC)
    2. manual_hmac()         — HMAC built step-by-step from hashlib primitives
    3. hmac_sha256()         — the production one-liner using Python's hmac module
    4. sign_message()        — sign a message with a key, returning hex digests
    5. verify_message()      — constant-time verification of a message+key against a tag
"""

import hashlib
import hmac

# SHA-256 parameters
_BLOCK_SIZE = 64            # SHA-256 processes messages in 512-bit (64-byte) blocks
_IPAD = 0x36                # inner padding byte from RFC 2104
_OPAD = 0x5c                # outer padding byte from RFC 2104


def _to_bytes(data: "str | bytes") -> bytes:
    """UTF-8 encode strings; pass bytes through untouched.

    Accepting bytes matters for crypto: RFC test vectors use raw byte
    values that are not valid UTF-8 text.
    """
    return data.encode("utf-8") if isinstance(data, str) else data


def plaintext_hash(message: "str | bytes") -> str:
    """Return the bare SHA-256 hex digest of a message (no key).

    Used in the demo to show that plain hashing provides integrity only:
    anyone can recompute it because no secret is involved.
    """
    return hashlib.sha256(_to_bytes(message)).hexdigest()


def manual_hmac(key: "str | bytes", message: "str | bytes") -> str:
    """Compute HMAC-SHA256 step by step, implementing RFC 2104 directly.

    This exists for academic clarity: it proves the student understands the
    construction rather than only calling hmac.new(). It must produce the
    same output as hmac_sha256().

    Steps (per RFC 2104):
        1. Key handling:
             - key longer than block size -> first hash it down
             - key shorter than block size -> right-pad with zero bytes
        2. inner hash  = H( (K' ^ ipad) || message )
        3. outer hash  = H( (K' ^ opad) || inner hash )
    """
    key_bytes = _to_bytes(key)
    msg_bytes = _to_bytes(message)

    # Step 1: normalise the key to exactly one block (64 bytes for SHA-256)
    if len(key_bytes) > _BLOCK_SIZE:
        key_bytes = hashlib.sha256(key_bytes).digest()
    key_bytes = key_bytes.ljust(_BLOCK_SIZE, b"\x00")   # zero-pad on the right

    # Step 2: inner hash — H( (K' ^ ipad) || m )
    block = bytes(b ^ _IPAD for b in key_bytes)
    inner = hashlib.sha256(block + msg_bytes).digest()

    # Step 3: outer hash — H( (K' ^ opad) || inner )
    block = bytes(b ^ _OPAD for b in key_bytes)
    return hashlib.sha256(block + inner).hexdigest()


def hmac_sha256(key: "str | bytes", message: "str | bytes") -> str:
    """Production HMAC-SHA256 using Python's standard library (RFC 2104 compliant).

    Returns the MAC as a lowercase hex string.
    """
    return hmac.new(_to_bytes(key), _to_bytes(message), hashlib.sha256).hexdigest()


def sign_message(message: str, key: str) -> dict:
    """Sign a message, returning everything the demo UI needs in one call."""
    return {
        "message": message,
        "sha256": plaintext_hash(message),
        "hmac": hmac_sha256(key, message),
    }


def verify_message(message: str, key: str, hmac_hex: str) -> bool:
    """Verify that (message, key) produces the given HMAC tag.

    Uses hmac.compare_digest() — a constant-time comparison — so the exact
    byte position where two tags first differ cannot be timed by an attacker.
    This matters in real deployments; worth mentioning in the viva.
    """
    expected = hmac_sha256(key, message)
    return hmac.compare_digest(expected, hmac_hex.strip().lower())


def abbreviate_hash(hex_str: str, prefix_len: int = 8, suffix_len: int = 8) -> str:
    """Safely abbreviate a hash or HMAC hex string for UI display.

    Never displays or logs any secret key.
    Example: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
             -> 'b0344c61...2e32cff7'
    """
    if not isinstance(hex_str, str):
        return ""
    s = hex_str.strip()
    if len(s) <= prefix_len + suffix_len + 3:
        return s
    return f"{s[:prefix_len]}...{s[-suffix_len:]}"


def build_replay_data(message: str, timestamp: "float | int | str", nonce: str) -> str:
    """Construct canonical authenticated string binding message, timestamp, and nonce.

    Crucial INS security principle:
    Freshness data (timestamp + nonce) must be included in the EXACT data
    authenticated by the HMAC tag. If an attacker modifies either in transit,
    the tag verification will immediately fail.
    """
    return f"{timestamp}:{nonce}:{message}"


def sign_replay_message(
    message: str, key: str, timestamp: "float | int | str", nonce: str
) -> dict:
    """Sign a replay-protected message package, binding timestamp and nonce."""
    authenticated_data = build_replay_data(message, timestamp, nonce)
    return {
        "message": message,
        "timestamp": timestamp,
        "nonce": nonce,
        "authenticated_data": authenticated_data,
        "hmac": hmac_sha256(key, authenticated_data),
    }


def verify_message_detailed(message: str, key: str, hmac_hex: str) -> dict:
    """Verify message and return structured security analysis details.

    Performs constant-time comparison and provides abbreviated hashes without
    exposing secret keys.
    """
    if not isinstance(hmac_hex, str):
        return {
            "valid": False,
            "crypto_valid": False,
            "received_hmac_short": "",
            "expected_hmac_short": abbreviate_hash(hmac_sha256(key, message)),
            "reason": "Malformed or non-string HMAC tag provided.",
        }

    expected = hmac_sha256(key, message)
    received = hmac_hex.strip().lower()
    valid = hmac.compare_digest(expected, received)

    return {
        "valid": valid,
        "crypto_valid": valid,
        "received_hmac_short": abbreviate_hash(received),
        "expected_hmac_short": abbreviate_hash(expected),
        "reason": (
            "Valid authentication: Message integrity verified and shared-secret key possession confirmed."
            if valid
            else "Verification failed: Recomputed HMAC does not match transmitted tag (message altered or incorrect key)."
        ),
    }
