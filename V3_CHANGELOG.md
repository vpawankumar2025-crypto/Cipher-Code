# V3 changes

## New capabilities

1. **Attack-origin world map** — `db.attack_map()` / `db._points_from_cases()`,
   `GET /api/dashboard/attack-map`, `AttackOriginMap` component in
   `static/index.html` (Leaflet + CARTO dark tiles). Per-case pins coloured by
   verdict, plus weighted heat clusters rounded to ~11 km so one datacentre
   doesn't become a pile of identical pins. Cases whose IP never resolved are
   reported as `unplottable` rather than plotted at (0, 0).

2. **ML explainability** — `ml_explain.py`. For a linear model on TF-IDF,
   `tfidf_value × coefficient` per term, summed with the intercept, *is* the
   model's log-odds. Verified: the probability rebuilt from the explanation
   matches `predict_proba` to 1e-7. Not an approximation like LIME/SHAP —
   say that if a judge asks about black boxes. Surfaced in the case detail
   panel and in the `/api/analyze` response as `explanation`.

3. **Real-time alerts** — `alerts.py`, hooked into `POST /api/analyze`.
   SMS (Twilio) + email (SMTP), reusing the OTP credentials. Fires on a daemon
   thread so a slow Twilio call can't delay the request; de-duplicated per
   sender domain so one campaign hitting 40 inboxes doesn't send 40 texts;
   threshold via `ALERT_MIN_SCORE`; every send written to the audit log.

4. **Hindi / Hinglish detection** — `language_router.py`,
   `generate_hindi_dataset.py`, `train_model_hi.py`. Devanagari-ratio plus a
   romanized-marker lexicon routes regional mail to a second classifier;
   a script-independent keyword layer scores fraud vocabulary either way.
   The Hindi model uses character n-grams because romanized Hinglish has no
   fixed spelling ("khata"/"khaata"/"khatha").
   **Its corpus is synthetic and template-generated** — the printed hold-out
   accuracy is optimistic by construction. Present it as "the routing and
   pipeline work end to end", not as a detection rate.

5. **CERT-In / cybercrime.gov.in export** — `cert_in_report.py`,
   `GET /api/cases/{id}/incident-report` (PDF) and `.json`. Pre-fills the
   reporting fields from the case. Marked DRAFT throughout; it files nothing
   and is not meant to.

6. **Tests + Docker** — `tests/` (runs fully offline; network enrichment is
   monkeypatched), `pytest.ini`, `Dockerfile`, `docker-compose.yml`,
   `.dockerignore`, `.gitignore`.

## Changes to existing files

- `scoring.py` — multilingual routing, regional keyword rule, explanation
  attached to the verdict payload.
- `db.py` — explanation stored inside `advanced_json` (no schema migration);
  `_points_from_cases()` and `attack_map()` added.
- `backend.py` — alert hook in `/api/analyze`; attack-map and incident-report
  endpoints; `static/` mounted at `/app`.
- `dashboard.html` → **`static/index.html`** (moved). The static mount serves
  only `static/`, never the project root — mounting the root would have
  published `.env`, the SQLite DB and the model pickles over HTTP.
- `requirements.txt` — `pytest`, `httpx`.
- `.env.example` — **the old version contained live credentials.** Replaced
  with placeholders. Rotate all of them: Gmail app password, Twilio API key,
  Google and Microsoft OAuth client secrets, `JWT_SECRET_KEY`.

## Before the demo

The map is empty until cases have resolvable public IPs. Analyze 8–10 `.eml`
files with `Received` headers from different countries first — a world map
with one pin is worse than no map.
