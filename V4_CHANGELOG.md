# V4 changes

## New capabilities

1. **Lookalike / typosquatted-domain detection** — `typosquat.py`. Edit-distance
   (plus homoglyph normalization and hyphen/word-insertion checks) against a
   watchlist of commonly-impersonated brands, including major Indian banks,
   UPI apps and government portals. Wired into `scoring.py` (+25 rule score,
   explanatory reason) and surfaced in the dashboard's "Lookalike-domain
   check" card and in the CERT-In report.

   Verified against this project's own `samples/phishing_email.eml`: its
   sender `security@paypa1-alerts.com` is correctly flagged as a PayPal
   lookalike (edit distance 1, hyphen/word insertion).

2. **Evidence integrity / chain of custody** — `evidence_integrity.py`.
   SHA-256 hash of the raw uploaded bytes computed at intake, before any
   parsing — this is the answer to "how do you know the evidence wasn't
   altered?" A hash-chained custody log (`ingested` → `scored`, extendable
   to `report_exported` etc.) makes tampering with any past entry detectable:
   changing one entry breaks every `chain_hash` after it.

   This is plain SHA-256 hashing, explicitly not framed as blockchain —
   say that plainly if asked. It's the same principle real forensic
   chain-of-custody logs use.

   New endpoint: `GET /api/cases/{id}/evidence-verify` recomputes the chain
   and reports whether it's intact, with the index of the first broken
   entry if not. Surfaced in the dashboard's "Evidence integrity" card with
   a "Verify custody chain" button, and in the CERT-In report as a new
   "Evidence integrity" section.

## Changes to existing files

- `scoring.py` — typosquat check added as a rule; `typosquat` result added
  to the returned verdict dict.
- `backend.py` — evidence hashed and a two-entry chain (`ingested`,
  `scored`) recorded on every `/api/analyze` call; `typosquat` and
  `evidence` added to the response; new `/api/cases/{id}/evidence-verify`
  endpoint.
- `db.py` — `save_case()` accepts `evidence` and `chain_entry`; new
  `append_evidence_chain()`; `_case_to_dict()` exposes `evidence_sha256`,
  `evidence_chain`, and `typosquat` at the top level (still stored inside
  `advanced_json`, so no schema migration). Older cases saved before this
  change simply show no evidence hash / an empty chain — nothing breaks.
- `cert_in_report.py` — new "Evidence integrity" section in the PDF and a
  "Lookalike-domain check" row in the technical-evidence table.
- `static/index.html` — two new cards in Advanced Threat Intelligence:
  lookalike-domain check, and evidence integrity (with a live chain-verify
  button). `AdvancedIntelligence` now receives `apiFetch` as a prop to make
  the verify call.
- `tests/test_v4_features.py` — new, covers both modules including the
  exact tamper- and reorder-detection cases for the hash chain.
- `tests/test_pipeline.py` / `tests/conftest.py` — extended to assert the
  typosquat finding on the project's own phishing sample, and to include
  the new fields in the shared `demo_case` fixture.

## Verified

- `typosquat.py` and `evidence_integrity.py` run standalone and via manual
  assertion runs (pytest unavailable offline in the build sandbox) — all
  pass, including tamper and reorder detection for the hash chain.
- `scoring.py` end-to-end on the real phishing sample: still scores
  Malicious/99, now with the typosquat reason present.
- `cert_in_report.py` PDF regenerated and visually checked — both new
  sections render correctly.
- Dashboard JSX re-parsed clean after all edits (TypeScript parser, JSX
  mode) — no syntax errors.
- **Not** runtime-tested: `db.py`'s new `save_case`/`append_evidence_chain`
  logic (no `sqlalchemy` available in the offline build sandbox). Reviewed
  by hand; run `pytest` yourself once before relying on it.
