# SentinelMail AI — V2 Change Log

## Version 2.0

### Added
- `advanced_security.py`: explainable AI enrichment, IOC extraction, URL/domain analysis, header forensics, timeline and relationship graph generation.
- `advanced_json` persistence on cases with automatic SQLite migration.
- `/api/cases/{case_id}/advanced` endpoint.
- `/api/dashboard/analytics` endpoint.
- Dashboard V2 Operations Overview and Alert Center.
- Case-level V2 Advanced Threat Intelligence panel.

### Compatibility
- Existing authentication, mailbox OAuth, ML classifier, scoring, reports and charts remain in place.
- Existing databases are migrated automatically on startup to add `advanced_json`.
- No new required dependencies.
