# SentinelMail AI — Full Prototype (matches pitch deck architecture)

SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## What's now REAL (not mocked) vs. what's still a documented stand-in

| Deck claim | Status |
|---|---|
| Python (FastAPI) backend | ✅ Real — `backend.py`, tested end-to-end |
| AI/ML model scores Safe/Suspicious/Malicious | ✅ Real trained model — `train_model.py` + `ml_classifier.py` (TF-IDF + Logistic Regression) |
| SPF/DKIM/DMARC validation | ✅ Real — parsed from `Authentication-Results` header in `eml_parser.py` |
| Sender IP extraction + geolocation | ✅ Real — `eml_parser.py` + `geoip_lookup.py` (needs internet) |
| VirusTotal / PhishTank threat-intel | ✅ Real API integration — `threat_intel.py` (needs a free `VT_API_KEY`; PhishTank works without a key but may rate-limit) |
| PostgreSQL case storage | ✅ Real ORM (SQLAlchemy) — runs on SQLite by default, **one env var** switches to real PostgreSQL |
| ReportLab forensic PDF | ✅ Real — `report_generator.py` |
| React-based analyst dashboard, review/override/export | ✅ Real — `dashboard.html` (React via CDN, no build step) |
| IMAP polling (Step 1 real-time ingestion) | ✅ Real — `imap_ingest.py` (needs your own inbox credentials to run live) |
| ML training data | ⚠️ **Synthetic** — see note below |

### Important honesty note on the ML model
This sandbox environment could not reach Kaggle/HuggingFace to download the real
"Phishing Email Dataset" / SpamAssassin corpus referenced in the original deck
(network here is restricted to package registries only). So `generate_dataset.py`
creates a synthetic-but-realistic labeled dataset instead, and `train_model.py`
trains a genuine scikit-learn model on it — this is a real, working ML classifier,
just trained on synthetic data rather than the real public datasets.

**On your own machine with full internet:** download the real Kaggle Phishing
Email Dataset or SpamAssassin corpus, format it as a CSV with `text,label` columns
(same as `phishing_dataset.csv`), and re-run `train_model.py` — the rest of the
pipeline needs zero changes. This is the single most valuable upgrade you can make
if you have any spare time before demo day.

Also note: the model scored 100% accuracy on synthetic test data — this is
expected (the synthetic data is templated and cleanly separable) and is
**not** a number to quote to judges as-is. State plainly that it's a training
placeholder pending the real dataset swap.

## Architecture (matches deck exactly)

```
Step 1: Email ingestion       → imap_ingest.py (live inbox) OR manual .eml upload
Step 2: Header/Auth/IP        → eml_parser.py  (SPF/DKIM/DMARC + originating IP)
Step 3: ML classification     → ml_classifier.py (trained model, phishing probability)
Step 4: GeoIP + threat intel  → geoip_lookup.py + threat_intel.py
Step 5: Verdict + report      → scoring.py (blends ML + rules) + report_generator.py
Step 6: Analyst dashboard     → dashboard.html (React) + backend.py (FastAPI API)
                                 review, override verdicts, export PDF
```

## Setup (10 minutes)

```bash
pip install -r requirements.txt

# 1. Train the ML model (creates phishing_model.pkl)
python3 train_model.py

# 2. Start the FastAPI backend
uvicorn backend:app --reload --port 8000

# 3. Open the dashboard — just open this file directly in a browser:
#    (no build step needed, it's plain HTML + React via CDN)
open dashboard.html        # macOS
# or just double-click dashboard.html / drag into Chrome
```

The dashboard talks to the backend at `http://localhost:8000` — make sure the
backend is running first.

## Optional: enable real threat-intel checks

```bash
export VT_API_KEY="your-free-virustotal-api-key"    # from virustotal.com/gui/join-us
```
Without this, VirusTotal checks gracefully report "no_api_key" instead of crashing.
PhishTank's public endpoint works without a key but may return 403 under rate limits
(as seen in our sandbox testing) — this is expected and disclosed, not a bug.

## Optional: switch to real PostgreSQL

```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/sentinelmail"
```
Default (no env var set) uses SQLite (`sentinelmail_cases.db`) — zero setup needed
for the demo. PostgreSQL wasn't installable in the sandbox used to build this
(package installation timed out), so it's implemented via SQLAlchemy so both
databases work identically — just install PostgreSQL locally and set this variable.

## Optional: live IMAP ingestion

```bash
export IMAP_HOST="imap.gmail.com"
export IMAP_USER="youraddress@gmail.com"
export IMAP_PASS="your-16-character-app-password"   # NOT your real password
python3 imap_ingest.py
```
Generate a Gmail App Password at myaccount.google.com/apppasswords (requires
2FA enabled). This polls your inbox every 30 seconds and automatically runs
new emails through the full pipeline, saving cases to the database.

## Demo script (what to show judges)

1. Open `dashboard.html` in a browser (backend already running).
2. Upload `samples/phishing_email.eml` — watch the case appear with a live
   ML confidence score (93.6%), failed SPF/DKIM/DMARC, and Malicious verdict.
3. Click the case row → show the full evidence panel.
4. Change the verdict dropdown → click **Save Override** → point out this is
   exactly the "analyst review and override" feature from the deck.
5. Click **Export Forensic PDF** → open the downloaded report live.
6. Upload `samples/clean_email.eml` → show it correctly scores Safe.
7. If asked "is this real ML?" — answer honestly: yes, a real trained
   scikit-learn model, currently trained on synthetic data as a placeholder
   for the Kaggle dataset (name this proactively, don't wait to be asked).

## Honest gap list (say this before judges find it)

- ML model trained on synthetic data, not the real Kaggle/SpamAssassin corpus (network-restricted dev environment) — one dataset swap away from production-grade
- VirusTotal needs a free API key to return real results; without one it degrades gracefully
- PostgreSQL not installed in the dev sandbox — SQLAlchemy makes this a one-line env var swap, verified against SQLite
- GeoIP uses the free ip-api.com service (needs internet); MaxMind GeoLite2 (as named in the deck) is a drop-in swap in `geoip_lookup.py` for offline/production use
- No automated test suite yet — all testing here was manual end-to-end verification via curl against the live API
