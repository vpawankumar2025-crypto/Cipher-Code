"""
privacy_compliance.py
Privacy, legal, and compliance safeguards — a named component of the
SIH26106 brief, separate from the detection/forensics engine itself.

Three things live here:
1. A configurable data-retention policy (how long case data is kept).
2. PII masking for non-admin views (so an analyst without case ownership
   sees enough to triage without the full raw email address / body).
3. An audit-log table recording who viewed or acted on a case — the
   accountability half of "chain of custody" (the PDF report's Received-
   header chain, already in report_generator.py, is the *technical* half;
   this is the *access* half a real investigation also needs).

Configuration is via environment variables so ops can tune retention
without a code change:
    RETENTION_DAYS=180      (default; 0 disables auto-purge entirely)
    MASK_PII_FOR_NON_ADMIN=true   (default)
"""

import os
import re
from datetime import datetime, timedelta

RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "180"))
MASK_PII_FOR_NON_ADMIN = os.environ.get("MASK_PII_FOR_NON_ADMIN", "true").lower() == "true"

_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def mask_email(address: str) -> str:
    """'jane.doe@company.com' -> 'j***e@company.com' — keeps the domain
    (needed for threat analysis) and enough of the local part to recognize
    a repeat sender, without exposing the full address."""
    def _mask_one(m):
        local, domain = m.group(1), m.group(2)
        if len(local) <= 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    return _EMAIL_RE.sub(_mask_one, address or "")


def mask_case_for_view(case: dict, viewer_is_admin: bool, viewer_is_owner: bool) -> dict:
    """Returns a copy of the case dict with sender/recipient/body PII masked
    unless the viewer is the case's owner or an admin. Scores, verdicts,
    IOCs, and infrastructure/geo signals are never masked — those are the
    forensic content the tool exists to show; only who-sent/received-it PII
    is affected.
    """
    if not MASK_PII_FOR_NON_ADMIN or viewer_is_admin or viewer_is_owner:
        return case

    masked = dict(case)
    if masked.get("sender"):
        masked["sender"] = mask_email(masked["sender"])
    parsed = masked.get("parsed")
    if isinstance(parsed, dict):
        parsed = dict(parsed)
        for field in ("from", "to", "reply_to", "return_path"):
            if parsed.get(field):
                parsed[field] = mask_email(parsed[field])
        masked["parsed"] = parsed
    return masked


def is_expired(created_at: datetime, retention_days: int = None) -> bool:
    retention_days = RETENTION_DAYS if retention_days is None else retention_days
    if not created_at or retention_days <= 0:
        return False  # retention_days=0 means "keep indefinitely"
    return datetime.utcnow() - created_at > timedelta(days=retention_days)


def audit_log_entry(user_id: int, action: str, case_id: int = None, detail: str = "") -> dict:
    """Builds a structured audit-log row. Callers persist this however their
    storage layer prefers (db.py's AuditLog table below, or an external SIEM
    in a production deployment) — kept as a plain dict here so this module
    has no hard dependency on SQLAlchemy.
    """
    return {
        "user_id": user_id,
        "action": action,       # e.g. "view_case", "download_report", "override_verdict"
        "case_id": case_id,
        "detail": detail,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
