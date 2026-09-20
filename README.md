# SentinelMail AI — Full Prototype (matches pitch deck architecture)

SIH26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

## Table of Contents

- [Run it](#run-it)
- [Current status at a glance (V1 → V4)](#current-status-at-a-glance-v1--v4)
- [What's now REAL vs. what's still a documented stand-in](#whats-now-real-not-mocked-vs-whats-still-a-documented-stand-in)
- [Architecture](#architecture-matches-deck-exactly)
- [Setup (10 minutes)](#setup-10-minutes)
- [Security note](#security-note-read-before-demo-day)
- [Optional: enable real threat-intel checks](#optional-enable-real-threat-intel-checks)
- [Optional: switch to real PostgreSQL](#optional-switch-to-real-postgresql)
- [Optional: live IMAP ingestion](#optional-live-imap-ingestion)
- [Optional: direct Gmail/Outlook connect (OAuth)](#optional-direct-gmailoutlook-connect-oauth-no-app-password)
- [Demo script](#demo-script-what-to-show-judges)
- [Known warnings you might see](#known-warnings-you-might-see-harmless)
- [Honest gap list](#honest-gap-list-say-this-before-judges-find-it)
- [V2 — Advanced Threat Investigation](#sentinelmail-ai-v2--advanced-threat-investigation)
- [V3 — Closing the SIH26106 brief's named gaps](#sentinelmail-ai-v3--closing-the-sih26106-briefs-named-gaps)
- [Judge Q&A — differentiation talking points](#judge-qa--differentiation-talking-points)
- [Tech Stack](#tech-stack)
- [License](#license)

## Run it

    cp .env.example .env      # fill in your OWN, ROTATED credentials — see note below
    docker compose up --build

Dashboard: http://localhost:8000/app/
API docs:  http://localhost:8000/docs

Without Docker:

    pip install -r requirements.txt
    python train_model.py && python train_model_hi.py
    uvicorn backend:app --reload --port 8000
    pytest                    # offline test suite, no network needed

## Current status at a glance (V1 → V4)

| Feature | Where | Since |
|---|---|---|
| Attack-origin world map (pins + heat clusters by sender IP) | `db.attack_map()` → `GET /api/dashboard/attack-map` → `AttackOriginMap` in `static/index.html` | V3 |
| ML explainability — top contributing words per verdict | `ml_explain.py` (exact term attribution: contributions + intercept reconstruct the model's log-odds, not a LIME/SHAP approximation) | V2 |
| Real-time SMS/email alerts on Malicious verdicts | `alerts.py`, hooked into `POST /api/analyze` — background thread, campaign de-duplication, threshold via `ALERT_MIN_SCORE` | V2 |
| Hindi / code-mixed Hinglish phishing detection | `language_router.py` + `generate_hindi_dataset.py` + `train_model_hi.py` (char n-gram model; synthetic corpus, see the docstrings) | V2 |
| CERT-In / cybercrime.gov.in incident report export | `cert_in_report.py` → `GET /api/cases/{id}/incident-report` (PDF) and `.json` — a reviewable DRAFT, files nothing | V2 |
| WHOIS domain-registration intelligence | `domain_intel.py` — registrar, registrant country, domain age; flags sub-90-day domains | V3 |
| VPN/Tor/cloud-hosting infrastructure correlation | `infra_intel.py` — Tor exit list + ip-api proxy/hosting flags + ASN keyword match | V3 |
| Campaign clustering (case management) | `db.list_campaigns()` → `GET /api/campaigns` | V3 |
| Privacy/retention/PII-masking + audit log | `privacy_compliance.py` | V3 |
| **Lookalike / typosquatted-domain detection** | `typosquat.py` — edit-distance + homoglyph checks against a watchlist incl. major Indian banks/UPI apps/govt portals; feeds `scoring.py` and the CERT-In report | **V4** |
| **Evidence integrity / chain of custody** | `evidence_integrity.py` — SHA-256 hash at intake + hash-chained custody log; `GET /api/cases/{id}/evidence-verify` re-verifies the chain and reports the first broken entry, if any | **V4** |
| Test suite + Docker | `tests/` (incl. `test_v4_features.py`), `pytest.ini`, `Dockerfile`, `docker-compose.yml` | V1–V4 |

See `V2_CHANGELOG.md`, `V3_CHANGELOG.md`, `V4_CHANGELOG.md` for the full detail behind each row.

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
| React-based analyst dashboard, review/override/export | ✅ Real — `static/index.html` (React via CDN, no build step) |
| IMAP polling (Step 1 real-time ingestion) | ✅ Real — `imap_ingest.py` (needs your own inbox credentials to run live) |
| ML training data | ✅ **Real** — Enron spam/ham corpus (34k real emails) + disclosed synthetic supplement |
| WHOIS / domain-registration intelligence | ✅ Real — `domain_intel.py` (needs internet; python-whois) |
| VPN/Tor/cloud-hosting infrastructure correlation | ✅ Real — `infra_intel.py` (Tor Project exit list + ip-api.com proxy/hosting flags + ASN keyword match) |
| Campaign clustering (case management) | ✅ Real — `db.list_campaigns()` + `GET /api/campaigns` |
| Privacy/retention/PII-masking safeguards | ✅ Real — `privacy_compliance.py` + audit-log table |
| Lookalike/typosquat domain detection | ✅ Real — `typosquat.py`, verified against this repo's own phishing sample (`security@paypa1-alerts.com` correctly flagged, edit distance 1) |
| Evidence integrity / chain of custody | ✅ Real — `evidence_integrity.py`, SHA-256 hash-chained log, tamper detection covered in `tests/test_v4_features.py` — explicitly plain hashing, not framed as blockchain |

### Note on the ML training data
`build_real_dataset.py` trains on a blend of two sources — say so plainly if
asked (see the script's own docstring for the full citation):

1. **Real data**: 6,000 emails (balanced) sampled from the Enron spam/ham
   corpus (34k real emails, an academic dataset used in published
   spam-filtering research) — genuine legitimate corporate email and genuine
   real-world spam.
2. **Disclosed synthetic supplement**: 1,000 additional samples covering
   OTP/KYC/gift-card/BEC-style phishing patterns the 2001 Enron-era corpus
   predates (from `generate_dataset.py`).

**The honest framing for judges:** "trained on a real 34k-email academic
corpus plus a disclosed synthetic supplement for modern attack patterns" —
not "trained on real phishing data" unqualified. The 98.4% hold-out accuracy
is a same-distribution split of this blended dataset, not an independent
real-world benchmark — say that plainly if pressed on the number.

If you have internet access before demo day, re-running
`python3 build_real_dataset.py` re-downloads a fresh Enron sample — no code
changes needed. Going further, swapping in a dedicated phishing-only corpus
(e.g. the Nazario phishing corpus) alongside Enron's ham would narrow the
gap between "spam" and "targeted phishing" even further.

## Architecture (matches deck exactly)

```
Step 1: Email ingestion       → imap_ingest.py / mailbox_oauth.py (live inbox) OR manual .eml upload
Step 2: Header/Auth/IP        → eml_parser.py  (SPF/DKIM/DMARC + originating IP)
Step 3: ML classification     → ml_classifier.py (trained model, phishing probability)
Step 4: GeoIP + threat intel  → geoip_lookup.py + threat_intel.py
Step 5: Domain + infra intel  → domain_intel.py (WHOIS) + infra_intel.py (VPN/Tor/hosting)
Step 6: Verdict + report      → scoring.py (blends ML + rules + domain/infra) + report_generator.py
Step 7: Case management       → db.list_campaigns() (groups related emails into campaigns)
Step 8: Privacy/compliance    → privacy_compliance.py (retention, PII masking, audit log)
Step 9: Analyst dashboard     → static/index.html (React) + backend.py (FastAPI API)
                                 review, override verdicts, export PDF
```

## Setup (10 minutes)

```bash
pip install -r requirements.txt

# 1. (Optional but recommended) rebuild the training dataset from the real
#    Enron spam/ham corpus -- needs internet once. Skips gracefully to the
#    fully-synthetic fallback if you're offline. phishing_dataset.csv already
#    ships pre-built from this step, so this is only needed to refresh it.
python3 build_real_dataset.py

# 2. Train the ML model (creates phishing_model.pkl)
python3 train_model.py

# 3. Start the FastAPI backend
uvicorn backend:app --reload --port 8000

# 4. Open the dashboard — just open this file directly in a browser:
#    (no build step needed, it's plain HTML + React via CDN)
open static/index.html     # macOS
# or just double-click static/index.html / drag into Chrome
# or, with the backend running: http://localhost:8000/app/
```

The dashboard talks to the backend at `http://localhost:8000` — make sure the
backend is running first.

## Security note (read before demo day)

`.env` is git-ignored and must **never** be committed or zipped up for
submission. If any credential in it was ever shared, committed, or sent in a
zip to a teammate, treat it as burned and rotate it — Gmail App Password,
Twilio Auth Token/API Key, Google & Microsoft OAuth client secrets, and
`JWT_SECRET_KEY` (`python -c "import secrets; print(secrets.token_hex(32))"`).
`.env.example` should only ever contain blank placeholders, never real values
even as a "temporary" convenience.

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

## Optional: direct Gmail/Outlook connect (OAuth, no app password)

Unlike the IMAP option above, this lets a user click "Connect Gmail" /
"Connect Outlook" in the dashboard and grant read-only access via a normal
OAuth consent screen — no app password to generate, and it works for
Outlook.com/Microsoft 365 accounts too. A background job (APScheduler) then
polls every connected mailbox on a timer and scores new mail automatically.

**Google Cloud Console** (console.cloud.google.com):
1. Create (or reuse) a project, then **APIs & Services → Credentials → Create
   Credentials → OAuth client ID**, application type **Web application**.
2. Add an **Authorized redirect URI** matching `GMAIL_OAUTH_REDIRECT_URI`
   below (default `http://localhost:8000/api/mailbox/callback/google`).
3. Enable the **Gmail API** for the project.
4. Copy the client ID and client secret into `.env`.

**Azure Portal** (portal.azure.com → Microsoft Entra ID → App registrations):
1. **New registration** — supported account types: "Personal Microsoft
   accounts and work/school accounts" (this is what `MS_OAUTH_TENANT=common`
   expects).
2. Under **Authentication**, add a **Web** platform redirect URI matching
   `MS_OAUTH_REDIRECT_URI` below (default
   `http://localhost:8000/api/mailbox/callback/microsoft`).
3. Under **Certificates & secrets**, create a new client secret.
4. Copy the application (client) ID and the secret value into `.env`.

```bash
# .env
GMAIL_OAUTH_CLIENT_ID="..."
GMAIL_OAUTH_CLIENT_SECRET="..."
GMAIL_OAUTH_REDIRECT_URI="http://localhost:8000/api/mailbox/callback/google"

MS_OAUTH_CLIENT_ID="..."
MS_OAUTH_CLIENT_SECRET="..."
MS_OAUTH_TENANT="common"
MS_OAUTH_REDIRECT_URI="http://localhost:8000/api/mailbox/callback/microsoft"

MAILBOX_POLL_INTERVAL_MINUTES=3
```

Both providers are requested with read-only scopes only
(`gmail.readonly` / `Mail.Read`) — SentinelMail never sends, deletes, or
modifies mail. Tokens are stored per-user in the `connected_mailboxes` table;
disconnecting from the dashboard deletes them immediately.

> **Security note:** the redirect URIs above are `http://localhost` for local
> dev only. In any real deployment, use `https://`, and register that exact
> HTTPS URI with Google/Microsoft — OAuth providers will reject a mismatched
> redirect URI.

## Demo script (what to show judges)

1. Open `static/index.html` in a browser, or http://localhost:8000/app/ (backend already running).
2. Upload `samples/phishing_email.eml` — watch the case appear with a live
   ML confidence score (97.9%), failed SPF/DKIM/DMARC, a recently-registered
   sender domain flagged by WHOIS, and a Malicious verdict (score 99/100).
3. Click the case row → show the full evidence panel: the attribution
   graph (sender domain → IP → infrastructure/WHOIS nodes → URLs), the
   risk breakdown by category, and the IOC list.
4. Open **Campaigns** (`GET /api/campaigns`) — upload `phishing_email.eml`
   a second time under a different filename first if you want two cases to
   cluster — show related emails from the same sender domain + IP grouped
   into one campaign, not just listed as separate isolated cases.
5. Change the verdict dropdown → click **Save Override** → point out this
   is logged to the audit table (`privacy_compliance.py`) for chain of custody.
6. Point out the **Lookalike-domain check** card — `paypa1-alerts.com` is
   flagged as a PayPal typosquat (edit distance 1), and the **Evidence
   integrity** card → click **Verify custody chain** live to show the
   SHA-256 hash chain is intact.
7. Click **Export Forensic PDF** → open the downloaded report live, and
   point out the Evidence Integrity and Lookalike-domain sections in it.
8. Upload `samples/clean_email.eml` → show it correctly scores Safe (score 3/100).
9. If asked "is this real ML?" — answer honestly: yes, a real trained
   scikit-learn model, trained on a real 34k-email academic corpus (Enron
   spam/ham) blended with a disclosed synthetic supplement for modern
   OTP/KYC/BEC patterns the 2001 corpus predates (name this proactively,
   don't wait to be asked — see the ML training data note above).

## Known warnings you might see (harmless)

- `InconsistentVersionWarning` from scikit-learn when loading `phishing_model.pkl`
  — means your installed scikit-learn version doesn't match the one the pickle
  was built with. Fixed by pinning `scikit-learn==1.8.0` in `requirements.txt`
  (matches the shipped model exactly). If you ever upgrade scikit-learn on
  purpose, just re-run `python3 train_model.py` to regenerate a matching pickle.
- `Error trying to connect to socket: closing socket` / a Windows `WinError 10054`
  in the console during analysis or mailbox sync — this is the `python-whois`
  library itself printing (not raising) whenever a registrar's WHOIS server is
  unreachable, rate-limits, or resets the connection. `domain_intel.py` already
  passes `quiet=True` and a 6s timeout to suppress this and fail fast; the case
  still analyzes correctly with `domain_intel.status: "error"` for that email.
  Some corporate/campus networks block outbound WHOIS (TCP port 43) entirely —
  test this on your actual demo network beforehand.

## Honest gap list (say this before judges find it)

- ML model's real-data component is spam/ham (Enron), not phishing-labeled specifically — blended with a synthetic phishing/BEC supplement to cover that gap; the hold-out accuracy is a same-distribution split, not an independent benchmark
- No free, reliable public botnet-IP list exists — `infra_intel.py` covers VPN/Tor/cloud-hosting but explicitly does NOT claim botnet detection (see `botnet_checked` field); a paid feed (AbuseIPDB, Spamhaus) would close this if budget allows
- WHOIS lookups go out to registrar servers over port 43, which some corporate/campus networks block — the pipeline degrades gracefully (reports `status: error`) rather than crashing, but test this on the actual demo network beforehand
- VirusTotal needs a free API key to return real results; without one it degrades gracefully
- PostgreSQL not installed in the dev sandbox — SQLAlchemy makes this a one-line env var swap, verified against SQLite
- GeoIP uses the free ip-api.com service (needs internet); MaxMind GeoLite2 (as named in the deck) is a drop-in swap in `geoip_lookup.py` for offline/production use
- `tests/` covers the core pipeline, V4 features (typosquat + evidence-chain tamper/reorder detection), and the attack map's coordinate-skipping guard — but `db.py`'s newer `save_case`/`append_evidence_chain` paths were reviewed by hand rather than exercised in every environment the model was built in (no `sqlalchemy` in that sandbox); run `pytest` yourself once per machine before relying on it
- Evidence integrity is plain SHA-256 hash-chaining, not blockchain — say that plainly if asked, since "chain of custody" invites the question

## SentinelMail AI V2 — Advanced Threat Investigation

This V2 update adds an explainable investigation layer on top of the existing ML + rules + threat-intelligence pipeline.

### V2 capabilities
- **Explainable AI risk attribution** — separates AI content, header/authentication, URL, threat-intelligence, attachment and infrastructure signals.
- **IOC extraction** — extracts IP addresses, domains, URLs, email addresses and hashes from analyzed messages.
- **URL/domain risk analysis** — detects non-HTTPS URLs, shorteners, suspicious TLDs, punycode, deep subdomains and other local anomalies without visiting the URL.
- **Header forensics** — analyzes From/Reply-To/Return-Path relationships, Received-hop depth and authentication failures.
- **Attack relationship graph** — maps email → sender domain → infrastructure → URLs → threat intelligence indicators.
- **Investigation timeline** — presents the major forensic stages and verdict evidence in chronological workflow order.
- **Alert Center** — highlights high-risk cases for analyst follow-up.
- **Threat Operations overview** — adds recent case-volume, recurring-domain and alert views.

### New API endpoints
- `GET /api/cases/{case_id}/advanced`
- `GET /api/dashboard/analytics?days=14`

No additional Python packages are required for the V2 layer. The enrichment is designed to degrade gracefully when optional external threat-intelligence keys or DNS resolution are unavailable.

## SentinelMail AI V3 — Closing the SIH26106 brief's named gaps

V3 adds the components the official SIH26106 brief names explicitly that V1/V2
didn't yet cover: domain-registration intelligence, infrastructure correlation,
campaign-level case management, and privacy/compliance safeguards.

### V3 capabilities
- **WHOIS domain intelligence** (`domain_intel.py`) — registrar, registrant
  country, and domain age; flags domains registered within the last 90 days
  as a strong phishing/impersonation signal.
- **Infrastructure correlation** (`infra_intel.py`) — correlates the
  originating IP against a live Tor exit-node list, ip-api.com's proxy/VPN
  and hosting flags, and a static cloud/hosting-provider keyword list (AWS,
  Azure, GCP, OVH, DigitalOcean, Hetzner, etc.). Honestly discloses what it
  does NOT cover (no free reliable botnet-IP list exists — see `botnet_checked`).
- **Campaign clustering** (`db.list_campaigns()`) — groups Malicious/Suspicious
  cases that share a sender domain AND an originating IP into one campaign,
  using an explainable rule rather than a black-box similarity model, so a
  jury/analyst can verify exactly why two emails were grouped.
- **Privacy, legal & compliance safeguards** (`privacy_compliance.py`) —
  configurable data-retention window with an automated daily purge job,
  PII masking for non-owner/non-admin viewers, and an `AuditLog` table
  recording every case view, verdict override, and report download (the
  accountability half of chain of custody — the PDF report's Received-header
  chain is the technical half).
- **Real training data** — `build_real_dataset.py` documents and reproduces
  the real Enron spam/ham corpus + disclosed synthetic-supplement blend used
  to retrain the model (see the ML training data note near the top of this
  file).

### New API endpoints
- `GET /api/campaigns?days=30`

### New Python packages
- `python-whois` (already added to `requirements.txt`)

## Judge Q&A — differentiation talking points

This problem statement gets a lot of submissions that are, at heart, a spam
filter with a dashboard. Lead the pitch with what actually sets this apart:

1. **"We don't just flag the email, we trace where it came from."** Most
   phishing detectors stop at Safe/Suspicious/Malicious. This one produces
   an attribution graph (sender domain → WHOIS → originating IP →
   infrastructure type → URLs → threat intel), which is what makes it a
   *forensic intelligence platform* rather than a consumer inbox filter —
   the exact distinction the brief draws.
2. **"It groups attacks, not just emails."** Campaign clustering means an
   analyst investigating one phishing email can immediately see every other
   email from the same attacker infrastructure, instead of triaging each
   one in isolation.
3. **"We built the compliance layer, not just the AI layer."** Retention
   policy, PII masking, and an audit trail are easy to skip under hackathon
   time pressure — most competing teams will have skipped them. Naming this
   unprompted signals the team read the whole brief, not just the ML part.
4. **"We can prove the evidence wasn't tampered with."** The SHA-256
   hash-chained custody log (`evidence_integrity.py`) means an analyst — or
   a jury — can click one button and mathematically verify nothing in a
   case was altered after intake. Say plainly that it's hash-chaining, not
   blockchain, before anyone asks.
5. **"We catch the impersonation, not just the payload."** `typosquat.py`
   flags lookalike domains (incl. Indian bank/UPI/government-portal
   watchlist entries) even when the ML/rules score alone might not — this
   targets a specific, common Indian phishing pattern by name.
6. **If asked "why hasn't anyone solved this already?"** — the honest answer
   is that most existing tools (Google/Microsoft's built-in filters, consumer
   antivirus suites) optimize for blocking spam at scale, not for producing
   an evidentiary, explainable forensic record an investigator or SOC analyst
   can act on. That's a genuinely different design goal, not a better spam filter.
7. **Rehearse a live upload, not a hardcoded demo.** Jury guidance for this
   exact statement flags hardcoded demos as a known red flag. Send a real
   test email to a connected inbox during the demo and let the pipeline
   score it live — see the demo script above.

## Tech Stack

| Layer | Technology |
|---|---|
| Backend / API | Python, FastAPI, Uvicorn |
| Database | SQLAlchemy ORM — SQLite by default, PostgreSQL via one env var |
| Machine Learning | scikit-learn (TF-IDF + Logistic Regression), trained on Enron + disclosed synthetic supplement |
| Frontend | React (via CDN, no build step) — `static/index.html` |
| PDF reporting | ReportLab |
| Threat intelligence | VirusTotal API, PhishTank, WHOIS (python-whois), Tor exit-node list, ip-api.com |
| Auth | JWT (python-jose), bcrypt/passlib, TOTP (pyotp), Google Sign-In |
| Alerts | Twilio (SMS), SMTP (email) |
| Scheduling | APScheduler (mailbox polling, retention purge) |
| Testing | pytest |
| Containerization | Docker, docker-compose |

## License

This project was built for submission to **Smart India Hackathon — SIH26106**.
No open-source license has been declared yet, so all rights are reserved by
the author(s) by default; the code is shared here for evaluation and
portfolio purposes. If you intend to reuse, fork, or build on this project,
please reach out first or add an explicit license (e.g. MIT, Apache-2.0)
before doing so.
