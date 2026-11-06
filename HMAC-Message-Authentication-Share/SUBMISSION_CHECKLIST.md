# SUBMISSION_CHECKLIST.md — HMAC-Based Message Authentication System

Final submission and pre-presentation checklist. Matches the final implementation exactly.

---

## 1. Final Project Structure

```
HMAC-Message-Authentication/
├── app.py                  # Flask app: signing, verifying, replay endpoints
├── hmac_core.py            # Crypto core: manual_hmac, hmac_sha256, sign, verify
├── replay_defense.py       # Thread-safe in-memory NonceCache & freshness validator
├── templates/
│   └── index.html          # Interactive 3-stage pipeline & live protocol audit log
├── static/
│   ├── style.css           # Styling
│   └── app.js              # Pipeline orchestration & API communication
├── tests/
│   ├── test_hmac_core.py   # 24 core tests (incl. RFC 4231 vectors)
│   ├── test_replay_defense.py # 10 replay defense & concurrency tests
│   └── test_api.py         # 34 API tests (Flask test client)
├── requirements.txt        # flask>=3.0 (single dependency)
├── README.md               # Full project documentation & Windows run guide
├── PRESENTATION_GUIDE.md   # Slide content, demo script, viva Q&A
└── SUBMISSION_CHECKLIST.md # This file
```

## 2. Required Files (must all be present in the submission)

- [ ] `app.py`
- [ ] `hmac_core.py`
- [ ] `replay_defense.py`
- [ ] `templates/index.html`
- [ ] `static/style.css`
- [ ] `static/app.js`
- [ ] `tests/test_hmac_core.py`
- [ ] `tests/test_replay_defense.py`
- [ ] `tests/test_api.py`
- [ ] `requirements.txt`
- [ ] `README.md`
- [ ] `PRESENTATION_GUIDE.md`
- [ ] `SUBMISSION_CHECKLIST.md`

## 3. Installation / Setup Commands

```bash
# 1. (Recommended) create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Linux / macOS (bash)
venv\Scripts\activate             # Windows

# 2. Install dependencies
pip install -r requirements.txt
```

No database, no environment variables, no other configuration required.

## 4. Run Command

```bash
python app.py
```

Application serves at: **http://127.0.0.1:5000**

## 5. Test Command

```bash
python -m unittest discover -s tests -v
```

## 6. Expected Test Result

```
Ran 32 tests in ~0.05s

OK
```

- 19 core tests (`test_hmac_core.py`) — RFC 4231 cases 1, 2, 3, 6; manual ↔ stdlib equivalence; verification behaviour; tag edge cases
- 13 API tests (`test_api.py`) — endpoint success & validation; tampered/wrong-key rejection; empty/malformed/wrong-length tag handling

**Expected status: 32/32 passing.**

## 7. Exact Live-Demo Sequence (single webpage)

| # | Action | Expected result |
|---|---|---|
| 1 | Open `http://127.0.0.1:5000` | Page shows 3 sections: Sender / Attacker / Receiver, defaults pre-filled |
| 2 | Confirm Message `Pay Alice $100 from account 42` and Key `shared-secret-key`; click **Generate HMAC** | Plain SHA-256 and HMAC-SHA256 displayed (different values) |
| 3 | Leave receiver key as `shared-secret-key`; click **Verify Message** | Green ✅ *Message is Authentic — Integrity Verified* |
| 4 | Click **Simulate Tampering ($100 → $900)** | Receiver's message box now shows `$900`; key and tag unchanged |
| 5 | Click **Verify Message** again | Red ❌ *Verification FAILED — Message Was Tampered With* |
| 6 | (Optional) Click **Reset**, regenerate, verify OK once, then change Receiver's Secret Key to `wrong-key` and click **Verify Message** | Red ❌ — invalid (key sensitivity) |
| 7 | (Optional) Click **Reset** to return to clean state | Defaults restored |

## 8. Files/Folders That Must NOT Be Submitted

Delete or exclude before packaging:

- [ ] `__pycache__/` directories (project root, `tests/`, anywhere)
- [ ] `*.pyc` / `*.pyo` files
- [ ] `venv/` (or any virtual environment folder)
- [ ] `.pytest_cache/`, `.mypy_cache/` (if present)
- [ ] Editor/OS artifacts: `.DS_Store`, `Thumbs.db`, `.vscode/`, `.idea/`
- [ ] Backup screenshots (keep these with YOU for the presentation, not in the submission — or only include them if your instructor requires demo evidence)

Suggested cleanup command (run from project root, before zipping):

```bash
find . -type d -name "__pycache__" -prune -exec rm -rf {} +
find . -type f \( -name "*.pyc" -o -name "*.pyo" -o -name ".DS_Store" -o -name "Thumbs.db" \) -delete
```

## 9. Final Pre-Presentation Checklist

- [ ] Clean submission packaged (structure per §1, exclusions per §8)
- [ ] `python -m unittest discover -s tests -v` → **32/32 OK** on the presentation machine
- [ ] `python app.py` starts; `http://127.0.0.1:5000` opens correctly on the presentation machine
- [ ] Full demo dry-run completed once (§7, steps 1–6)
- [ ] Backup screenshots of all demo outcomes available offline
- [ ] `PRESENTATION_GUIDE.md` reviewed: 12 slides ready, demo script rehearsed, viva Q&A read
- [ ] Browser zoom ≥110%, unrelated tabs closed
- [ ] Terminal ready in project folder for an on-the-spot test-suite demonstration if challenged
