"""
app.py — Flask backend for the "Interactive Message Integrity and Authentication Lab".

Endpoints:
    POST /api/sign                   { "message": "...", "key": "..." }
                                     -> { "message", "sha256", "hmac" }
    POST /api/verify                 { "message": "...", "key": "...", "hmac": "...", "details": bool }
                                     -> { "valid": bool } or detailed analysis object
    POST /api/replay/sign            { "message": "...", "key": "...", "nonce": "...", "timestamp": float }
                                     -> { "message", "timestamp", "nonce", "authenticated_data", "hmac", "sha256" }
    POST /api/replay/simulate-stale  { "message": "...", "key": "...", "age_seconds": float }
                                     -> { "message", "timestamp", "nonce", "authenticated_data", "hmac", "simulated_stale": true }
    POST /api/replay/verify          { "message": "...", "key": "...", "timestamp": float, "nonce": "...", "hmac": "..." }
                                     -> { "valid": bool, "crypto_valid": bool, "freshness_valid": bool, "nonce_valid": bool, "code": "...", "reason_code": "...", "reason": "...", ... }
    POST /api/replay/reset           {}
                                     -> { "status": "cleared", "cached_count": 0 }

Run:  python app.py   then open http://127.0.0.1:5000
"""

import secrets
import time
from flask import Flask, jsonify, render_template, request

from hmac_core import (
    abbreviate_hash,
    build_replay_data,
    hmac_sha256,
    plaintext_hash,
    sign_message,
    sign_replay_message,
    verify_message,
    verify_message_detailed,
)
from replay_defense import (
    TIMESTAMP_TOLERANCE_SECONDS,
    default_nonce_cache,
)

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the demo page."""
    return render_template("index.html")


def _json_body() -> "dict | None":
    """Return the request JSON object, or None if missing/invalid."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _error(message: str, status: int):
    """Uniform JSON error response for bad client input."""
    return jsonify({"error": message}), status


@app.route("/api/sign", methods=["POST"])
def api_sign():
    body = _json_body()
    if body is None:
        return _error("Request body must be JSON.", 400)

    message = body.get("message", "")
    key = body.get("key", "")

    if not isinstance(message, str) or not isinstance(key, str):
        return _error("'message' and 'key' must be strings.", 400)
    if not message:
        return _error("'message' must not be empty.", 400)
    if not key:
        return _error("'key' must not be empty (HMAC needs a secret).", 400)

    return jsonify(sign_message(message, key))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    body = _json_body()
    if body is None:
        return _error("Request body must be JSON.", 400)

    message = body.get("message", "")
    key = body.get("key", "")
    hmac_hex = body.get("hmac", "")

    if not all(isinstance(v, str) for v in (message, key, hmac_hex)):
        return _error("'message', 'key' and 'hmac' must be strings.", 400)
    if not message or not key or not hmac_hex:
        return _error("'message', 'key' and 'hmac' must not be empty.", 400)

    # If detailed analysis is requested (e.g. from the Security Analysis Panel)
    if body.get("details") or body.get("analyze"):
        detail = verify_message_detailed(message, key, hmac_hex)
        return jsonify(detail)

    valid = verify_message(message, key, hmac_hex)
    return jsonify({"valid": valid})


@app.route("/api/replay/sign", methods=["POST"])
def api_replay_sign():
    """Sign a message binding timestamp and nonce to defend against replay."""
    body = _json_body()
    if body is None:
        return _error("Request body must be JSON.", 400)

    message = body.get("message", "")
    key = body.get("key", "")

    if not isinstance(message, str) or not isinstance(key, str):
        return _error("'message' and 'key' must be strings.", 400)
    if not message:
        return _error("'message' must not be empty.", 400)
    if not key:
        return _error("'key' must not be empty (HMAC needs a secret).", 400)

    # Optional timestamp provided by client, otherwise generate current UTC epoch seconds
    ts_val = body.get("timestamp")
    if ts_val is not None:
        try:
            timestamp = float(ts_val)
        except (ValueError, TypeError):
            return _error("'timestamp' must be a valid number.", 400)
    else:
        timestamp = round(time.time(), 2)

    # Optional nonce provided by client, otherwise generate cryptographically secure 16-hex nonce
    nonce_val = body.get("nonce")
    if nonce_val is not None:
        if not isinstance(nonce_val, str) or not nonce_val.strip():
            return _error("'nonce' must be a non-empty string if provided.", 400)
        nonce = nonce_val.strip()
    else:
        nonce = secrets.token_hex(8)

    result = sign_replay_message(message, key, timestamp, nonce)
    # Include bare sha256 to allow visual comparison in UI
    result["sha256"] = plaintext_hash(message)
    return jsonify(result)


@app.route("/api/replay/simulate-stale", methods=["POST"])
def api_replay_simulate_stale():
    """Generate an educational stale-packet fixture genuinely signed with a past timestamp.

    Demonstration Helper (Classroom/Viva scope):
    Allows demonstrators to show timestamp expiration rejection without waiting 2 minutes.
    The HMAC tag is genuinely computed by the server for that past timestamp. When delivered
    to the normal verification endpoint, the cryptographic check passes, but the timestamp
    freshness check fails.
    """
    body = _json_body()
    if body is None:
        return _error("Request body must be JSON.", 400)

    message = body.get("message", "")
    key = body.get("key", "")

    if not isinstance(message, str) or not isinstance(key, str):
        return _error("'message' and 'key' must be strings.", 400)
    if not message:
        return _error("'message' must not be empty.", 400)
    if not key:
        return _error("'key' must not be empty (HMAC needs a secret).", 400)

    # Default to 180 seconds in the past (outside ±120s tolerance)
    try:
        age_seconds = float(body.get("age_seconds", 180.0))
    except (ValueError, TypeError):
        age_seconds = 180.0

    if age_seconds <= TIMESTAMP_TOLERANCE_SECONDS:
        age_seconds = TIMESTAMP_TOLERANCE_SECONDS + 60.0

    stale_timestamp = round(time.time() - age_seconds, 2)
    nonce = secrets.token_hex(8)
    authenticated_data = build_replay_data(message, stale_timestamp, nonce)
    hmac_tag = hmac_sha256(key, authenticated_data)

    return jsonify({
        "message": message,
        "timestamp": stale_timestamp,
        "nonce": nonce,
        "authenticated_data": authenticated_data,
        "hmac": hmac_tag,
        "sha256": plaintext_hash(message),
        "age_seconds": age_seconds,
        "simulated_stale": True,
    })


@app.route("/api/replay/verify", methods=["POST"])
def api_replay_verify():
    """Verify an authenticated message while enforcing timestamp freshness and nonce-reuse defense.

    All security decisions are made here on the backend.
    Checks performed in strict order:
      1. Cryptographic HMAC check over canonical envelope. If invalid -> Reject immediately.
         (Prevents nonce-cache poisoning; invalid packets NEVER consume nonces).
      2. Timestamp freshness check against ±120s tolerance window. If stale -> Reject.
      3. Nonce uniqueness check and atomic consumption under thread-lock. If reused -> Reject.
    """
    body = _json_body()
    if body is None:
        return _error("Request body must be JSON.", 400)

    message = body.get("message", "")
    key = body.get("key", "")
    hmac_hex = body.get("hmac", "")
    nonce = body.get("nonce", "")
    ts_val = body.get("timestamp")

    if not all(isinstance(v, str) for v in (message, key, hmac_hex, nonce)):
        return _error("'message', 'key', 'hmac' and 'nonce' must be strings.", 400)
    if not message or not key or not hmac_hex or not nonce:
        return _error("'message', 'key', 'hmac' and 'nonce' must not be empty.", 400)

    if ts_val is None:
        return _error("'timestamp' is required for replay-protected verification.", 400)
    try:
        timestamp = float(ts_val)
    except (ValueError, TypeError):
        return _error("'timestamp' must be a valid number.", 400)

    # Step 1: Cryptographic HMAC check over the exact canonical payload
    authenticated_data = build_replay_data(message, timestamp, nonce)
    expected_hmac = hmac_sha256(key, authenticated_data)
    crypto_valid = verify_message(authenticated_data, key, hmac_hex)

    received_short = abbreviate_hash(hmac_hex)
    expected_short = abbreviate_hash(expected_hmac)

    if not crypto_valid:
        # Cryptographic failure: message/timestamp/nonce altered OR wrong key.
        # Notice: default_nonce_cache is NOT called here! Prevents nonce cache poisoning.
        return jsonify({
            "valid": False,
            "crypto_valid": False,
            "freshness_valid": False,
            "nonce_valid": None,
            "code": "CRYPTO_MISMATCH",
            "reason_code": "crypto_mismatch",
            "reason": (
                "Cryptographic verification failed: Received HMAC tag does not match expected tag. "
                "Either the message, timestamp, or nonce was tampered with in transit, or the key is incorrect."
            ),
            "received_hmac_short": received_short,
            "expected_hmac_short": expected_short,
        })

    # Step 2: Freshness & Nonce Reuse Defense (enforced on the backend)
    freshness_ok, reason_code = default_nonce_cache.check_and_consume(nonce, timestamp)

    if reason_code == "reused_nonce":
        return jsonify({
            "valid": False,
            "crypto_valid": True,
            "freshness_valid": False,
            "timestamp_valid": True,
            "nonce_valid": False,
            "code": "REUSED_NONCE",
            "reason_code": "reused_nonce",
            "reason": (
                f"Replay attack detected: Nonce '{nonce}' has already been consumed. "
                "The HMAC tag was cryptographically valid, but this duplicate packet was rejected by the receiver."
            ),
            "received_hmac_short": received_short,
            "expected_hmac_short": expected_short,
        })

    if reason_code == "expired_timestamp":
        return jsonify({
            "valid": False,
            "crypto_valid": True,
            "freshness_valid": False,
            "nonce_valid": None,
            "code": "TIMESTAMP_EXPIRED",
            "reason_code": "expired_timestamp",
            "reason": (
                f"Freshness check failed [TIMESTAMP_EXPIRED]: Timestamp is outside the allowable tolerance window "
                f"(±{int(TIMESTAMP_TOLERANCE_SECONDS)}s). Message is expired/stale."
            ),
            "received_hmac_short": received_short,
            "expected_hmac_short": expected_short,
        })

    if reason_code == "future_timestamp":
        return jsonify({
            "valid": False,
            "crypto_valid": True,
            "freshness_valid": False,
            "nonce_valid": None,
            "code": "FUTURE_TIMESTAMP",
            "reason_code": "future_timestamp",
            "reason": "Freshness check failed [FUTURE_TIMESTAMP]: Timestamp is in the future beyond acceptable clock drift.",
            "received_hmac_short": received_short,
            "expected_hmac_short": expected_short,
        })

    if not freshness_ok:
        return jsonify({
            "valid": False,
            "crypto_valid": True,
            "freshness_valid": False,
            "nonce_valid": None,
            "code": reason_code.upper(),
            "reason_code": reason_code,
            "reason": f"Freshness validation failed: {reason_code}.",
            "received_hmac_short": received_short,
            "expected_hmac_short": expected_short,
        })

    # Message is both authentic and fresh!
    return jsonify({
        "valid": True,
        "crypto_valid": True,
        "freshness_valid": True,
        "nonce_valid": True,
        "code": "AUTHENTICATED_FRESH",
        "reason_code": "authenticated_fresh",
        "reason": (
            "Message authenticated and accepted: Cryptographic HMAC signature is valid, "
            "timestamp is fresh, and nonce is unique."
        ),
        "received_hmac_short": received_short,
        "expected_hmac_short": expected_short,
    })


@app.route("/api/replay/reset", methods=["POST"])
def api_replay_reset():
    """Reset the in-memory nonce cache for lab demonstrations."""
    default_nonce_cache.clear()
    return jsonify({"status": "cleared", "cached_count": default_nonce_cache.count()})


@app.errorhandler(404)
def not_found(_):
    return _error("Unknown endpoint.", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return _error("Method not allowed on this endpoint.", 405)


if __name__ == "__main__":
    # debug=False for anything beyond local demos — debug mode exposes a
    # remote-code-execution console if left on when exposed to a network.
    app.run(host="127.0.0.1", port=5000, debug=False)
