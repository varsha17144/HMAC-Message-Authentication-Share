# PRESENTATION_GUIDE.md — Interactive Message Integrity & Authentication Lab

Presentation-ready guide for an undergraduate **Information and Network Security** project.
Source of truth: the integrated implementation (`hmac_core.py`, `replay_defense.py`, `app.py`, `templates/index.html`, `static/`, `tests/`) and `README.md`.

Wording and conceptual rules followed throughout:
- HMAC provides **message integrity** and **shared-secret-based authenticity**.
- HMAC is **not** called a digital signature (avoids non-repudiation confusion).
- No claim of non-repudiation (shared symmetric key).
- No claim of confidentiality (HMAC does not encrypt).
- Integrated protocol workflow: **Sender ➔ Network / Attacker ➔ Receiver ➔ Live Audit Log**.
- Clear distinction between local classroom demonstration scope (in-memory cache) and production requirements (distributed durable cache like Redis).
- Test status: **68/68 passing**.

---

# PART 1 — SLIDE-BY-SLIDE CONTENT (12 SLIDES)

---

## SLIDE 1
**SLIDE TITLE:** Interactive Message Integrity and Authentication Lab  
**PURPOSE:** Professional opening; establish subject, course context, and presenters.  
**CONTENT:**
- Title: Interactive Message Integrity & Authentication Lab
- Subtitle: Integrated Protocol Pipeline for Message Integrity, Authenticity & Replay Defense (RFC 2104)
- Presented by: [Member 1 Name — Roll No] · [Member 2 Name — Roll No]
- Department: [Department Name] · Course: Information and Network Security
- Guide: [Faculty Guide Name] · Academic Year [20XX–XX]  
**SPEAKER NOTES:** "Good morning. We present an interactive laboratory showcasing an integrated message authentication pipeline: from packet creation at the sender, to live in-transit packet tampering and replay attacks on the network, to multi-factor verification at the receiver."

---

## SLIDE 2
**SLIDE TITLE:** Problem Statement — Integrity, Tampering & Replay Threats  
**PURPOSE:** Establish why plain transmission, bare hashing, and stateless authentication fall short.  
**CONTENT:**
- **Threat 1: Active In-Transit Tampering:**
  - An on-path attacker modifies plaintext messages in transit.
  - A plain SHA-256 hash gives **integrity only** (attacker can recompute the hash for their modified message).
  - Solution: Keyed-Hash Message Authentication Code (**HMAC**).
- **Threat 2: Replay of Valid Messages:**
  - HMAC is stateless: it confirms *who* signed and *what* was signed, but not *when*.
  - An attacker capturing a valid `(message, HMAC)` pair can retransmit it later (e.g. duplicating a transaction).
  - Solution: Binding **timestamps and unique nonces** into the authenticated envelope.  
**SPEAKER NOTES:** "A bare hash fails against tampering because anyone can rehash. But even with HMAC, an attacker can replay a captured valid message. Our lab demonstrates solutions to both problems in a unified workflow."

---

## SLIDE 3
**SLIDE TITLE:** Laboratory Objectives  
**PURPOSE:** List concrete, implementation-backed project goals.  
**CONTENT:**
1. Implement RFC 2104 compliant HMAC-SHA256 tags using shared secret keys.
2. Bind timestamps and unique cryptographic nonces into an unambiguous canonical authenticated payload: `timestamp:nonce:message`.
3. Provide an integrated Sender ➔ Network/Attacker ➔ Receiver pipeline where real packets are inspected and manipulated.
4. Support dynamic message tampering while preserving the sender's original HMAC tag.
5. Demonstrate replay attack defense using an atomic server-side nonce cache and sliding timestamp tolerance (±120s).
6. Enable live demonstration of stale packets without waiting 2 minutes via a safe educational fixture.
7. Validate all operations with a live protocol audit log and **68 automated tests**.  
**SPEAKER NOTES:** "Every feature demonstrated in our user interface is backed by rigorous backend validation and comprehensive automated tests."

---

## SLIDE 4
**SLIDE TITLE:** Cryptographic Properties — Hashing vs HMAC vs Encryption  
**PURPOSE:** Address the most common viva questions and avoid terminology confusion.  
**CONTENT:**

| Security Property | SHA-256 Hash | HMAC-SHA256 | Symmetric Encryption (AES) | Digital Signatures (RSA/ECDSA) |
|---|---|---|---|---|
| **Integrity** | ✅ (accidental corruption) | ✅ (cryptographic tamper detection) | ❌ (unless in AEAD mode) | ✅ |
| **Authenticity** | ❌ (no secret key) | ✅ (shared secret possession) | ❌ (unless authenticated) | ✅ (asymmetric identity) |
| **Confidentiality** | ❌ (does not encrypt) | ❌ (message is readable plaintext) | ✅ (ciphertext hides data) | ❌ |
| **Non-Repudiation**| ❌ | ❌ (both parties share key) | ❌ | ✅ (private key unique to sender) |

**SPEAKER NOTES:** "Remember the distinction: HMAC guarantees integrity and authenticity, but does NOT encrypt and does NOT provide non-repudiation because both parties share the symmetric key."

---

## SLIDE 5
**SLIDE TITLE:** HMAC-SHA256 Construction (RFC 2104)  
**PURPOSE:** Explain formula, key derivation, and constant-time tag comparison.  
**CONTENT:**
- **Formula:** $\text{HMAC}(K, M) = H\big( (K' \oplus \text{opad}) \parallel H((K' \oplus \text{ipad}) \parallel M) \big)$
- **Key Normalization ($K'$):**
  - Key longer than 64-byte block $\rightarrow$ hash first: $K' = H(K)$.
  - Key shorter than 64-byte block $\rightarrow$ right-pad with zeros to 64 bytes.
- **Fixed Constants:** Inner pad $\text{ipad} = 0\text{x}36 \times 64$, Outer pad $\text{opad} = 0\text{x}5c \times 64$.
- **Constant-Time Verification:** Uses `hmac.compare_digest()` to eliminate timing side-channel attacks that could leak tag bytes.  
**SPEAKER NOTES:** "HMAC hashes the message with an inner-padded key derivation, then hashes that intermediate result with an outer-padded derivation. In verification, constant-time comparison prevents timing attacks."

---

## SLIDE 6
**SLIDE TITLE:** Integrated Replay Defense & Freshness Validation  
**PURPOSE:** Explain the canonical envelope, freshness tolerance, and nonce caching.  
**CONTENT:**
- **Canonical Authenticated Envelope:**
  $$\text{Authenticated Data} = \text{timestamp} \parallel \text{nonce} \parallel \text{message}$$
  $$\text{HMAC Tag} = \text{HMAC-SHA256}(K, \text{Authenticated Data})$$
- **Receiver-Side Validation Pipeline (in strict order):**
  1. *HMAC Verification:* Tag recomputed over envelope. If mismatch $\rightarrow$ Reject (`CRYPTO_MISMATCH`). *Nonce is NOT consumed.*
  2. *Timestamp Freshness Window:* Must be within $\pm 120\text{s}$ tolerance. If older $\rightarrow$ Reject (`TIMESTAMP_EXPIRED`). *Nonce is NOT consumed.*
  3. *Atomic Nonce Cache:* Protected by `threading.Lock()` to prevent race conditions. If nonce already exists $\rightarrow$ Reject (`REUSED_NONCE`). Otherwise, cache nonce and Accept (`AUTHENTICATED_FRESH`).  
**SPEAKER NOTES:** "Notice the strict order: if the HMAC is invalid or the timestamp is stale, the nonce is never consumed. This prevents an attacker from poisoning the nonce cache."

---

## SLIDE 7
**SLIDE TITLE:** System Architecture & Integrated Data Flow  
**PURPOSE:** Show end-to-end communication between frontend and Flask backend.  
**CONTENT:**
- **Stage 1 (Sender):** User enters message and key $\rightarrow$ Calls `POST /api/replay/sign` $\rightarrow$ Generates timestamp, nonce, and HMAC tag.
- **Stage 2 (Network & Attacker):** Intercepts live packet in transit. User can deliver unmodified, tamper with message (diff view), replay captured packet, or test custom edits.
- **Stage 3 (Receiver):** Calls `POST /api/replay/verify` $\rightarrow$ Evaluates HMAC, timestamp freshness, and nonce uniqueness.
- **Stage 4 (Audit Log):** Logs every HTTP transaction in real time with server timestamps and response codes.  
**SPEAKER NOTES:** "All decisions are made by the Flask backend. The browser acts strictly as a thin relay and visualization dashboard."

---

## SLIDE 8
**SLIDE TITLE:** Implementation Details & Technology Stack  
**PURPOSE:** Present the code organization and dependencies.  
**CONTENT:**

| Component | Implementation | Role |
|---|---|---|
| **Web Server** | Flask 3.0+ (Python 3.10+) | Serves frontend and REST API |
| **Crypto Core** | Python standard library `hmac`, `hashlib` | RFC 2104 compliant HMAC-SHA256 & canonical envelope |
| **Replay Defense** | `threading.Lock` + dictionary store | Thread-safe atomic nonce consumption and expiration |
| **Frontend** | HTML5, CSS3, Vanilla ES6 JavaScript | Clean light-theme, zero client-side frameworks |
| **Test Harness** | Python `unittest` | 68 automated tests (RFC 4231 vectors, API, race tests) |

- Zero external crypto libraries required: fully transparent and inspectable.  
**SPEAKER NOTES:** "We chose Python's standard library for cryptography so the mathematical construction is completely transparent to the examiner."

---

## SLIDE 9
**SLIDE TITLE:** Security Analysis Panel & Educational Insights  
**PURPOSE:** Highlight structured verification and clear separation of concerns.  
**CONTENT:**
- **Verification Outcomes & Concise Explanations:**
  - Clearly reports whether failure is due to message tampering, key mismatch, or nonce reuse.
- **Abbreviated HMAC Display:**
  - Shows shortened tags (`b0344c61...2e32cff7`) for visual comparison without leaking secret keys.
- **Cryptographic vs Freshness Separation:**
  - Distinguishes between tag mismatch (crypto failure) and replayed packet (freshness failure).
- **Classroom Demo vs Production Scope:**
  - In-memory cache is ideal for single-instance classroom demonstration.
  - Production deployments require distributed, durable key-value storage (e.g. Redis cluster with atomic SETNX and TTL) and synchronized NTP clocks.  
**SPEAKER NOTES:** "Our Security Analysis Panel explicitly tells the examiner what failed and why, and distinguishes cryptographic integrity from freshness."

---

## SLIDE 10
**SLIDE TITLE:** Testing & Verification — 68/68 Tests Passing  
**PURPOSE:** Present automated test evidence.  
**CONTENT:**

| Test Suite | Count | Verification Scope |
|---|---|---|
| `test_hmac_core.py` | 24 | RFC 4231 official vectors (cases 1, 2, 3, 6), manual $\leftrightarrow$ stdlib match, detailed verify, avalanche effect |
| `test_replay_defense.py` | 10 | Fresh nonce acceptance, duplicate rejection, expired timestamps, clock drift, thread-safety, pruning |
| `test_api.py` | 34 | End-to-end API tests: `/api/sign`, `/api/verify`, `/api/replay/sign`, `/api/replay/simulate-stale`, `/api/replay/verify`, tamper detection, replay rejection, stale timestamp rejection, nonce-cache poisoning prevention, concurrent duplicate delivery race test, cache reset |

- **Total:** 68 unit and integration tests passing in ~0.15s.  
**SPEAKER NOTES:** "Correctness is anchored to official IETF RFC 4231 test vectors, proving our implementation matches the global standard independently of our own code."

---

## SLIDE 11
**SLIDE TITLE:** Live Demonstration Flow  
**PURPOSE:** Outline the interactive demonstration steps for the panel.  
**CONTENT:**
- **Step 1: Normal Delivery** ➔ Create packet ➔ Deliver unmodified ➔ ✅ Accepted (`AUTHENTICATED_FRESH`).
- **Step 2: Replay Attack** ➔ Click "Replay Captured Packet" ➔ 🛡️ Blocked (`REUSED_NONCE`). Tag is valid, but nonce was consumed!
- **Step 3: Dynamic Tampering** ➔ Click "Tamper With Message" ➔ ❌ Rejected (`CRYPTO_MISMATCH`). Tag preserved, message altered.
- **Step 4: Stale Packet** ➔ Click "Simulate Stale Packet" ➔ ⏳ Rejected (`TIMESTAMP_EXPIRED`). Valid HMAC, but stale timestamp.
- **Step 5: Wrong Key** ➔ Change receiver key to `wrong-key` ➔ ❌ Rejected (`CRYPTO_MISMATCH`).  
**SPEAKER NOTES:** "In our live demo, every attack scenario operates on the live packet in transit and receives an authoritative backend verdict."

---

## SLIDE 12
**SLIDE TITLE:** Conclusion & Key Takeaways  
**PURPOSE:** Final wrap-up and viva transition.  
**CONTENT:**
- **Key Takeaways:**
  1. **Bare Hash:** Detects accidental error, not intentional modification.
  2. **HMAC:** Solves tampering and authenticity using a shared secret.
  3. **Freshness Envelope:** Nonces + timestamps solve replay attacks.
  4. **Security Boundaries:** HMAC does not encrypt and does not provide non-repudiation.
- **Summary:**
  - Robust, educational implementation validated against RFC 4231 standards.
  - Clean separation of cryptographic verification and freshness validation.  
**SPEAKER NOTES:** "A hash detects changes; HMAC detects changes and proves key possession; nonces and timestamps prove the message is fresh and not replayed. We now invite your questions."

---

# PART 2 — LIVE DEMO SCRIPT (3–5 MINUTES)

### Step 1: Create & Deliver a Genuine Packet (Normal Flow)
1. Open `http://127.0.0.1:5000`.
2. In **Stage 1 (Sender)**, notice the default message `Transfer 250 units to account 9821` and key `shared-secret-key`. Click **Create & Sign Packet**.
3. Point out the generated fields: Message, Timestamp, Nonce, Canonical Envelope `timestamp:nonce:message`, and HMAC Tag. Notice the packet has populated Stage 2 (Network).
4. In **Stage 2 (Network)**, click **Deliver Unmodified Packet**.
5. In **Stage 3 (Receiver)**, observe the result:
   - Green banner: **Packet ACCEPTED — Message Authentic & Fresh**.
   - Cryptographic Check: **PASS**.
   - Timestamp Freshness: **FRESH (VALID)**.
   - Nonce Check: **UNIQUE (CONSUMED)**.
   - Decision: **ACCEPTED** (`AUTHENTICATED_FRESH`).
6. Point to **Stage 4 (Audit Log)**: The transaction is logged with its timestamp and server code.

### Step 2: Replay Attack Demonstration
1. In Stage 2 (Network), click **Replay Captured Packet**.
2. Notice the network transmits the exact captured packet with the previously consumed nonce and original tag.
3. In Stage 3 (Receiver), observe the verdict:
   - Yellow/warning banner: **Replay Attack BLOCKED — Duplicate Nonce Detected**.
   - Cryptographic Check: **PASS (MATCH)** — *Emphasize to the examiner that the HMAC tag was cryptographically valid!*
   - Timestamp Freshness: **FRESH (VALID)**.
   - Nonce Check: **REUSED (BLOCKED)**.
   - Decision: **REJECTED (REPLAY)** (`REUSED_NONCE`).
4. In Stage 4 (Audit Log), point out the logged `REPLAY_ATTEMPT` and `REUSED_NONCE` server response.

### Step 3: Dynamic Tampering Attack
1. In Stage 1, click **Create & Sign Packet** to make a fresh packet.
2. In Stage 2, click **Tamper With Message**.
3. Notice that ` [TAMPERED]` is appended to the message, while the sender's original HMAC tag is strictly preserved. Point out the Tamper Diff indicator.
4. In Stage 3 (Receiver), observe the verdict:
   - Red banner: **Verification FAILED — Cryptographic Mismatch**.
   - Cryptographic Check: **FAIL (MISMATCH)**.
   - Nonce Check: **UNCHECKED** (*Explain that invalid packets do not consume nonces, preventing cache poisoning*).
   - Decision: **REJECTED (TAMPERED)** (`CRYPTO_MISMATCH`).

### Step 4: Stale Packet Demonstration (Without Waiting 2 Minutes)
1. In Stage 1, click **Simulate Stale Packet (Age: 3m ago)**.
2. Point out that the server has generated a genuine packet whose timestamp is 180s in the past, with a mathematically genuine HMAC tag matching that timestamp.
3. In Stage 2, click **Deliver Unmodified Packet**.
4. In Stage 3 (Receiver), observe the verdict:
   - Red banner: **Stale Packet REJECTED — Timestamp Expired**.
   - Cryptographic Check: **PASS (MATCH)** — The tag matches!
   - Timestamp Freshness: **EXPIRED (STALE)** — Outside ±120s tolerance.
   - Nonce Check: **UNCHECKED**.
   - Decision: **REJECTED (EXPIRED)** (`TIMESTAMP_EXPIRED`).

### Step 5: Wrong Key & Reset
1. In Stage 3, change the Receiver's Secret Key to `wrong-key`.
2. In Stage 2, click **Deliver Current In-Transit Packet** $\rightarrow$ Fails with `CRYPTO_MISMATCH`.
3. In Stage 4, click **Reset Nonce Cache** $\rightarrow$ Show that the receiver cache is cleared for fresh trials.

---

# PART 3 — TOP VIVA QUESTIONS & CONCISE ANSWERS

1. **What is HMAC and how is it defined?**
   HMAC (Keyed-Hash Message Authentication Code, RFC 2104) is a cryptographic construction combining a hash function with a secret key: $\text{HMAC}(K, M) = H((K' \oplus \text{opad}) \parallel H((K' \oplus \text{ipad}) \parallel M))$. It guarantees integrity and authenticity.

2. **Why does plain SHA-256 fail to provide authenticity?**
   Plain SHA-256 uses no secret key. Anyone can compute the hash of any arbitrary message. If an attacker modifies a message in transit, they can simply recompute its SHA-256 hash, and the receiver cannot detect the attack.

3. **Why is standard HMAC vulnerable to replay attacks?**
   HMAC is stateless. It verifies that the message was authentic when created, but not when it was sent. An adversary who captures a valid `(message, HMAC)` pair can resend that exact unchanged packet repeatedly, and the receiver will accept it each time.

4. **How does our system prevent replay attacks?**
   We bind a timestamp and a unique nonce into the data authenticated by the HMAC: $\text{HMAC}(K, \text{timestamp} \parallel \text{nonce} \parallel \text{message})$. The receiver checks: (1) timestamp is within $\pm 120\text{s}$ tolerance, and (2) nonce has not been recorded previously in the nonce cache.

5. **Why MUST the timestamp and nonce be included in the data authenticated by HMAC?**
   If timestamp or nonce were outside the HMAC tag, an attacker could change them in transit (e.g. updating the timestamp to "now" or generating a new nonce) without invalidating the tag, completely bypassing replay defense.

6. **Why is `hmac.compare_digest()` used instead of `==`?**
   Standard string equality returns false at the first differing byte, creating a timing side channel where comparison time leaks the prefix of the tag. `compare_digest` runs in constant time, preventing timing attacks.

7. **Does HMAC provide confidentiality?**
   No. HMAC is not encryption. The message travels as readable plaintext. Confidentiality requires an encryption algorithm such as AES or TLS.

8. **Does HMAC provide non-repudiation?**
   No. Because both sender and receiver share the same symmetric secret key, either party could mathematically compute a valid tag. Digital signatures using asymmetric cryptography (RSA/ECDSA) are required for non-repudiation.

9. **What are ipad and opad in RFC 2104?**
   They are fixed inner and outer padding constants specified by RFC 2104: $\text{ipad} = 0\text{x}36$ repeated to block size (64 bytes for SHA-256) and $\text{opad} = 0\text{x}5c$ repeated to block size. They create two distinct, independent key derivations from a single shared secret.

10. **What is nonce-cache poisoning and how does our system prevent it?**
    If a receiver consumed a nonce before verifying the HMAC tag or timestamp, an attacker could send bogus packets with target nonces to consume them and block future legitimate packets. Our system checks the HMAC tag and timestamp *before* consuming the nonce. Invalid packets never consume nonces.

11. **Why is the in-memory nonce cache not suitable for production?**
    In-memory state is lost on server restart, and cannot be shared across multiple backend worker processes or servers. Production systems require a durable, coordinated distributed cache like Redis (using atomic `SET key val NX EX <window>`).

12. **How does our implementation avoid race conditions in nonce checking?**
    The check and consumption of a nonce occur atomically inside a `threading.Lock()`. No other thread can read or write to the cache between the existence check and the insertion. This is validated by our concurrent race test.

13. **What is RFC 4231?**
    RFC 4231 publishes official IETF test vectors for HMAC-SHA256. Our unit tests verify our implementation against Test Cases 1, 2, 3, and 6, proving standard compliance independently of our own code.

14. **Why are cryptographic verification and replay checks distinguished in the Security Analysis Panel?**
    Because they detect fundamentally different attacks: tag mismatch means active message corruption or wrong key; replay detection means a genuine past message is being fraudulently reused.

---

# PART 4 — PRE-VIVA CHECKLIST

- [ ] Run test suite: `.\venv\Scripts\python.exe -m unittest discover tests -v` $\rightarrow$ Confirm **68/68 tests OK**.
- [ ] Run application: `.\venv\Scripts\python.exe app.py` $\rightarrow$ Running on `http://127.0.0.1:5000`.
- [ ] Browser open at `http://127.0.0.1:5000`.
- [ ] Step 1 (Normal Delivery) tested $\rightarrow$ Accepted.
- [ ] Step 2 (Replay Attack) tested $\rightarrow$ Blocked with `REUSED_NONCE`.
- [ ] Step 3 (Tamper Message) tested $\rightarrow$ Rejected with `CRYPTO_MISMATCH`.
- [ ] Step 4 (Simulated Stale Packet) tested $\rightarrow$ Rejected with `TIMESTAMP_EXPIRED`.
- [ ] Step 5 (Wrong Key) tested $\rightarrow$ Rejected with `CRYPTO_MISMATCH`.
- [ ] Audit log verified in real-time.
