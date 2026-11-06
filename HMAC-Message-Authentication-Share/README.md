# Interactive Message Integrity and Authentication Lab

An educational laboratory for **Information and Network Security** demonstrating how
**HMAC (Hash-based Message Authentication Code, RFC 2104)** provides **message integrity**
and **shared-secret authenticity**, and how binding **nonces and timestamps** defends
against **replay attacks**.

The system features an integrated, realistic message-authentication workflow:
**Sender** ➔ **Network / Attacker (In-Transit Packet Inspection, Tampering & Replay)** ➔ **Receiver (Cryptographic & Freshness Verification)** ➔ **Live Protocol Audit Log**.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Integrated Architecture & Workflow](#integrated-architecture--workflow)
3. [Core Cryptographic Concepts (RFC 2104)](#core-cryptographic-concepts-rfc-2104)
4. [Replay Attack Defense & Freshness Validation](#replay-attack-defense--freshness-validation)
5. [Educational Stale-Packet Demonstration](#educational-stale-packet-demonstration)
6. [Technology Stack](#technology-stack)
7. [Project Structure](#project-structure)
8. [Installation and Setup](#installation-and-setup)
9. [How to Run the Application](#how-to-run-the-application)
10. [Laboratory Walkthrough](#laboratory-walkthrough)
11. [Testing and Validation](#testing-and-validation)
12. [Security Considerations & Viva Insights](#security-considerations--viva-insights)
13. [Limitations & Production Requirements](#limitations--production-requirements)

---

## Key Features

### 1. Integrated Sender ➔ Network/Attacker ➔ Receiver Pipeline
- Replay protection is integrated into the core transmission pipeline rather than existing as a disconnected card with canned buttons.
- The audience sees the actual generated packet traverse the network, can tamper with or replay it, and sees the receiver evaluate it in real time.

### 2. Sender — Authenticated Packet Generation
- Arbitrary message and secret key entry (no hardcoded amounts or scenarios).
- Generates current timestamp and a cryptographically unpredictable unique 16-hex nonce.
- Computes HMAC-SHA256 over the canonical envelope `timestamp:nonce:message`.
- Displays the full outgoing packet and contrasts plain SHA-256 with HMAC-SHA256.

### 3. Network & Attacker — Live Packet Manipulation
- Shows the actual live packet in transit.
- **Deliver Unmodified Packet:** Delivers the genuine packet straight to the receiver.
- **Tamper With Message:** Dynamically modifies the message while strictly preserving the sender's original HMAC tag. Shows a visual before-and-after diff.
- **Replay Captured Packet:** Resends a previously delivered genuine packet with the exact same nonce and timestamp.
- **Deliver Custom In-Transit Packet:** Allows testing arbitrary field edits.

### 4. Receiver — Real Verification Decisions
- All security decisions are made by the Flask backend.
- Structured Security Analysis Panel with 3 distinct evaluations:
  1. **HMAC Cryptographic Check:** [PASS / FAIL] (Transmitted vs Recomputed tag).
  2. **Timestamp Freshness Check:** [FRESH / EXPIRED (STALE) / UNCHECKED] (±120s tolerance).
  3. **Nonce Uniqueness Check:** [UNIQUE (CONSUMED) / REUSED (BLOCKED) / UNCHECKED].
- Clear, distinct server codes: `AUTHENTICATED_FRESH`, `CRYPTO_MISMATCH`, `REUSED_NONCE`, `TIMESTAMP_EXPIRED`, `FUTURE_TIMESTAMP`.
- Nonce-cache poisoning prevention: invalid packets never consume nonces.

### 5. Educational Stale-Packet Demonstration
- Safe educational stale-packet generator (`POST /api/replay/simulate-stale`) allows instructors to demonstrate timestamp expiration rejection without waiting 2 minutes.
- Generates a genuinely signed packet with a timestamp 3 minutes in the past. When verified, the cryptographic check passes while the freshness check fails specifically with `TIMESTAMP_EXPIRED`.

### 6. Live Protocol Audit Log
- Real-time chronological audit trail of all actual server requests and responses.
- Displays timestamps, event types, status badges, and technical reason codes.
- Powered strictly by backend JSON responses.

---

## Integrated Architecture & Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FLASK BACKEND (app.py)                           │
│                                                                             │
│   POST /api/sign                   POST /api/verify                         │
│   POST /api/replay/sign            POST /api/replay/simulate-stale          │
│   POST /api/replay/verify          POST /api/replay/reset                   │
│           │                                    │                            │
│           ▼                                    ▼                            │
│   ┌───────────────┐                  ┌─────────────────────────┐            │
│   │ hmac_core.py  │                  │    replay_defense.py    │            │
│   │  RFC 2104 /   │                  │ Thread-Safe Nonce Cache │            │
│   │  HMAC-SHA256  │                  │  & Sliding Expiration   │            │
│   └───────────────┘                  └─────────────────────────┘            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▲ JSON (fetch)
┌──────────────────────────────────────┴──────────────────────────────────────┐
│                    BROWSER INTERFACE (HTML + CSS + JS)                      │
│                                                                             │
│  [1. SENDER]             [2. NETWORK / ATTACKER]         [3. RECEIVER]      │
│  • Message & Key         • In-Transit Packet Inspector   • Secret Key Check │
│  • Timestamp & Nonce     • Deliver Unmodified Packet     • HMAC Verify      │
│  • HMAC-SHA256 Tag       • Tamper Message (Diff View)    • Freshness Check  │
│  • Stale Packet Option   • Replay Captured Packet        • Nonce Check      │
│                                                          • Security Panel   │
│                                                                             │
│  [4. LIVE PROTOCOL AUDIT LOG] (Real-time chronological events & Cache Reset) │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Cryptographic Concepts (RFC 2104)

HMAC combines a cryptographic hash function (SHA-256) with a secret key using a nested construction:

$$\text{HMAC}(K, m) = H( (K' \oplus \text{opad}) \parallel H( (K' \oplus \text{ipad}) \parallel m ) )$$

where:
- $K'$ is the key normalized to the SHA-256 block size (64 bytes): hashed if longer than 64 bytes, zero-padded if shorter.
- $\text{ipad} = 0\text{x}36 \times 64$, $\text{opad} = 0\text{x}5c \times 64$.
- Constant-time verification is enforced via `hmac.compare_digest()` to eliminate timing side-channel attacks.

---

## Replay Attack Defense & Freshness Validation

### Canonical Freshness Envelope
To prevent replay, sender and receiver bind message contents, timestamp, and unique nonce:

$$\text{Authenticated Data} = \text{timestamp} \parallel \text{nonce} \parallel \text{message}$$
$$\text{Tag} = \text{HMAC-SHA256}(K, \text{Authenticated Data})$$

Because timestamp and nonce are inside the authenticated data, an attacker cannot modify them without invalidating the HMAC tag.

### Backend Verification Pipeline
1. **Cryptographic Tag Check:** Recompute HMAC over `timestamp:nonce:message` with $K$. Compare against transmitted tag using `hmac.compare_digest()`. If mismatch $\rightarrow$ Reject (`CRYPTO_MISMATCH`). *Nonce is NOT consumed.*
2. **Timestamp Freshness:** Verify that $|t_{\text{now}} - t_{\text{msg}}| \le \text{tolerance}$ ($\pm 120\text{s}$). If expired $\rightarrow$ Reject (`TIMESTAMP_EXPIRED`). *Nonce is NOT consumed.*
3. **Atomic Nonce Cache:** Under a `threading.Lock()`, verify if `nonce` has already been recorded:
   - If present in cache $\rightarrow$ Reject as replay (`REUSED_NONCE`).
   - If not present $\rightarrow$ Add `nonce` to cache and Accept (`AUTHENTICATED_FRESH`).

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend** | Python 3.10+ / Flask | Lightweight, inspectable web framework |
| **HMAC Core** | Python `hmac` & `hashlib` | RFC 2104 & RFC 4231 standard implementation |
| **Replay Defense** | Python `threading.Lock` + in-memory store | Thread-safe atomic nonce consumption and expiration |
| **Frontend** | HTML5 / CSS3 / Vanilla ES6 JavaScript | Clean light-theme, responsive academic user interface |
| **Testing** | Python `unittest` | 68 automated unit and API test cases |

---

## Project Structure

```
HMAC-Message-Authentication/
├── app.py                  # Flask web application & REST API routing
├── hmac_core.py            # RFC 2104 manual & stdlib HMAC, canonical envelope builder
├── replay_defense.py       # Thread-safe in-memory NonceCache & freshness validator
├── templates/
│   └── index.html          # Unified 3-stage pipeline & live protocol audit log
├── static/
│   ├── style.css           # Academic light-theme stylesheet
│   └── app.js              # Client-side pipeline orchestration & audit logging
├── tests/
│   ├── test_hmac_core.py   # RFC 4231 test vectors, manual↔stdlib equivalence, helpers
│   ├── test_replay_defense.py # NonceCache freshness, replay rejection, threading, pruning
│   └── test_api.py         # End-to-end API tests for all routes, validation, race conditions
├── requirements.txt        # Flask dependency
├── PRESENTATION_GUIDE.md   # Presentation slides, viva defense guide & demo script
└── README.md               # Project documentation
```

---

## Installation and Setup (Windows Quickstart)

### Prerequisites
- **Python 3.10 or higher** installed and available in your `PATH`.
- Verify your Python installation in PowerShell or Command Prompt:
  ```powershell
  python --version
  ```

### 1. Navigate to the Project Folder
Open PowerShell or Command Prompt and change directory into the project folder:
```powershell
cd HMAC-Message-Authentication-Share
```

### 2. Create a Virtual Environment
Create a clean, isolated virtual environment named `venv`:
```powershell
python -m venv venv
```

### 3. Activate the Virtual Environment
- **PowerShell:**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
  *(Note: If PowerShell reports that script execution is disabled, enable it for your current session with `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` and retry activation).*
- **Command Prompt (`cmd.exe`):**
  ```cmd
  venv\Scripts\activate.bat
  ```
- **Git Bash / Linux / macOS (optional):**
  ```bash
  source venv/bin/activate
  ```

### 4. Install Requirements
Install Flask (the only external dependency):
```powershell
pip install -r requirements.txt
```

---

## Configuration and Secrets

- **Zero Real Secrets or Cloud Accounts Needed:** The application runs entirely locally. It does not require API keys, external databases, or cloud services.
- **Default Educational Values:**
  - **Shared Secret Key:** `shared-secret-key` (pre-filled for immediate testing; you can enter any arbitrary key).
  - **Sample Message:** `Transfer 250 units to account 9821` (you can enter any text).
- **Environment Variables:** None required. All cryptography and freshness logic runs in-process.

---

## How to Run the Application

Ensure the virtual environment is activated, then launch the Flask server:

```powershell
python app.py
```

Open your web browser and navigate to:
👉 **http://127.0.0.1:5000**

To stop the server, press `Ctrl + C` in your terminal window.

---

## Laboratory Walkthrough

### 1. Normal Authentic Delivery
1. In **Stage 1 (Sender)**, enter any message and click **Create & Sign Packet**.
2. The packet appears in **Stage 2 (Network)** as `UNTOUCHED GENUINE`.
3. Click **Deliver Unmodified Packet**.
4. In **Stage 3 (Receiver)**, the packet is **ACCEPTED** (`AUTHENTICATED_FRESH`). The cryptographic check passes, timestamp is fresh, and nonce is consumed.
5. In **Stage 4 (Audit Log)**, observe the logged event with timestamp and server response code.

### 2. Message Tampering Attack
1. In Stage 1, click **Create & Sign Packet**.
2. In Stage 2, click **Tamper With Message**.
3. Notice ` [TAMPERED]` is appended to the in-transit message, while the sender's original HMAC tag is preserved. The diff indicator highlights the change.
4. The receiver immediately rejects the packet with **REJECTED (TAMPERED)** (`CRYPTO_MISMATCH`).

### 3. Replay Attack
1. Having completed a normal delivery (Step 1), click **Replay Captured Packet** in Stage 2.
2. The exact same packet (with the already-consumed nonce) is transmitted across the network.
3. The receiver reports:
   - Cryptographic Check: **PASS** (the tag was mathematically valid).
   - Nonce Check: **REUSED (BLOCKED)**.
   - Verdict: **REJECTED (REPLAY)** (`REUSED_NONCE`).

### 4. Stale Packet Demonstration (Simulated 3m Delay)
1. In Stage 1, click **Simulate Stale Packet (Age: 3m ago)**.
2. A genuine packet is generated with a timestamp from 3 minutes ago and a valid matching HMAC tag.
3. In Stage 2, click **Deliver Unmodified Packet**.
4. The receiver reports:
   - Cryptographic Check: **PASS** (the HMAC tag is genuine).
   - Timestamp Freshness: **EXPIRED (STALE)**.
   - Nonce Check: **UNCHECKED** (nonce cache is protected from poisoning).
   - Verdict: **REJECTED (EXPIRED)** (`TIMESTAMP_EXPIRED`).

### 5. Wrong Key Attack
1. Create a packet in Stage 1.
2. In Stage 3, change the Receiver's Secret Key to `wrong-key`.
3. In Stage 2, click **Deliver Unmodified Packet**.
4. Receiver rejects with `CRYPTO_MISMATCH` because key mismatch produces a different HMAC tag.

---

## Testing and Validation

Run the test suite using Python's `unittest` discover runner:

```bash
python -m unittest discover tests -v
```

**Status: 68 / 68 tests passing.**

| Test Suite | Test Count | Scope of Coverage |
|---|---|---|
| `test_hmac_core.py` | 24 | RFC 4231 vectors (cases 1, 2, 3, 6), manual $\leftrightarrow$ stdlib match, detailed verify, avalanche effect, hash abbreviation |
| `test_replay_defense.py` | 10 | Fresh nonce acceptance, duplicate rejection, expired timestamps, clock drift, thread-safety, pruning |
| `test_api.py` | 34 | End-to-end API tests: `/api/sign`, `/api/verify`, `/api/replay/sign`, `/api/replay/simulate-stale`, `/api/replay/verify`, tamper detection, replay rejection, stale timestamp rejection, nonce-cache poisoning prevention, concurrent duplicate delivery race test, cache reset |

---

## Security Considerations & Viva Insights

1. **Constant-Time Comparison (`hmac.compare_digest`):**
   Standard string equality (`==`) exits at the first mismatching byte, enabling side-channel timing attacks. Constant-time comparison ensures elapsed time is independent of byte differences.
2. **Freshness Binding:**
   Timestamp and nonce must be included inside the data authenticated by the HMAC tag. If they were outside, an attacker could forge them without invalidating the tag.
3. **Nonce-Cache Poisoning Prevention:**
   The receiver verifies the cryptographic tag and timestamp bounds *before* consuming the nonce. Invalid or stale packets never consume nonces.
4. **Atomic Nonce Consumption:**
   Nonce checking and insertion occur atomically under `threading.Lock()`, preventing concurrent race conditions.
5. **Security Boundaries:**
   - **Confidentiality:** ❌ Not provided (HMAC does not encrypt).
   - **Non-Repudiation:** ❌ Not provided (symmetric shared key).
   - **Integrity & Authenticity:** ✅ Provided.
   - **Freshness:** ✅ Provided via timestamp + nonce binding.

---

## Limitations & Production Requirements

> [!WARNING]
> **Academic Demonstration Scope:**
> The replay defense implemented here uses an in-memory cache for local classroom and viva demonstrations. It is **not production-ready** as-is.

### Production Requirements for Real-World Deployments:
1. **Durable Distributed Cache:** The in-memory cache resets on server restart and cannot coordinate across multiple Flask/Gunicorn worker processes. Production systems require a distributed store (e.g., Redis cluster using atomic `SET key val NX EX <window>`).
2. **Clock Synchronization:** Timestamp validation requires reliable server and client clock synchronization using NTP (Network Time Protocol).
3. **Transport Security (TLS):** Plain HTTP on localhost does not provide transport-layer confidentiality or channel binding. HMAC should operate within an encrypted TLS session.
4. **Secure Key Management:** In production, secret keys should be securely provisioned via HSM or secret managers (e.g., HashiCorp Vault, AWS KMS), not typed into web forms.
