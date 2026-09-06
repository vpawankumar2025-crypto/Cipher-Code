"""
mailbox_poller.py
Background job: for every connected (OAuth) mailbox, fetch messages received
since the last sync, run each through the same pipeline manual .eml uploads
go through (parse -> geolocate -> threat-intel -> score -> save_case), and
record the sync outcome. This is what makes connected inboxes show up in the
dashboard without anyone uploading anything.
"""

import os
import tempfile
from datetime import datetime

import db
import mailbox_oauth
from eml_parser import parse_eml
from geoip_lookup import geolocate_ip
from threat_intel import check_links
from scoring import score_email


def _ensure_fresh_token(mailbox) -> str:
    """Returns a valid access token, refreshing it first if it's expired or
    about to be (a small buffer avoids racing the actual expiry)."""
    buffer_seconds = 60
    if mailbox.token_expires_at and (mailbox.token_expires_at - datetime.utcnow()).total_seconds() > buffer_seconds:
        return mailbox.access_token

    refreshed = mailbox_oauth.refresh_access_token(mailbox.provider, mailbox.refresh_token)
    db.update_mailbox_tokens(mailbox.id, refreshed["access_token"], refreshed["expires_at"])
    return refreshed["access_token"]


def sync_mailbox(mailbox) -> dict:
    """Runs one sync cycle for a single ConnectedMailbox row. Never raises —
    errors are caught and recorded on the mailbox row so one broken connection
    doesn't take down the poll loop for everyone else.

    Idempotent by design: each message is skipped if a case with its filename
    already exists (db.case_exists), and sync progress is persisted even when
    a later message in the same batch fails — the failure is still recorded
    via `error`, but it no longer forces a retry over messages this cycle
    already processed successfully. Without both of these, a single bad or
    rate-limited message caused every message before it in the batch to be
    silently re-scored and re-inserted as a duplicate case on every retry."""
    cases_created = 0
    try:
        access_token = _ensure_fresh_token(mailbox)
        message_ids = mailbox_oauth.list_new_message_ids(mailbox.provider, access_token, mailbox.last_synced_at)

        for message_id in message_ids:
            filename = f"{mailbox.provider}:{mailbox.email_address}:{message_id}"
            if db.case_exists(mailbox.user_id, filename):
                continue

            raw_bytes = mailbox_oauth.fetch_raw_message(mailbox.provider, access_token, message_id)

            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                tmp.write(raw_bytes)
                tmp_path = tmp.name
            try:
                parsed = parse_eml(tmp_path)
                geo = geolocate_ip(parsed.get("originating_ip"))
                ti = check_links(parsed.get("links", []))
                verdict = score_email(parsed, geo, ti)
                db.save_case(parsed, geo, verdict, ti, filename=filename, user_id=mailbox.user_id)
                cases_created += 1
            finally:
                os.unlink(tmp_path)

        db.update_mailbox_sync_state(mailbox.id, synced_at=datetime.utcnow())
        return {"mailbox_id": mailbox.id, "new_cases": cases_created, "error": None}

    except Exception as e:
        # Record progress made before the failure so a retry only replays the
        # message(s) that actually failed, not the whole batch.
        db.update_mailbox_sync_state(mailbox.id, synced_at=datetime.utcnow(), error=str(e))
        return {"mailbox_id": mailbox.id, "new_cases": cases_created, "error": str(e)}


def poll_all_mailboxes():
    for mailbox in db.all_active_mailboxes():
        sync_mailbox(mailbox)


def start_scheduler():
    """Called once at backend startup. Returns the scheduler so it can be
    shut down cleanly (or ignored — daemonic by default)."""
    from apscheduler.schedulers.background import BackgroundScheduler
    from auth_config import MAILBOX_POLL_INTERVAL_MINUTES

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(poll_all_mailboxes, "interval", minutes=MAILBOX_POLL_INTERVAL_MINUTES, id="mailbox_poll")
    scheduler.start()
    return scheduler
