"""
imap_ingest.py
Real-time email ingestion via IMAP polling, as described in the pitch deck's
Step 1: "Email ingestion (IMAP polling or uploaded .eml file)".

Usage:
    export IMAP_HOST="imap.gmail.com"
    export IMAP_USER="youraddress@gmail.com"
    export IMAP_PASS="your-app-password"     # use an App Password, not your real password
    python3 imap_ingest.py

For Gmail: enable IMAP in settings and generate an App Password
(myaccount.google.com/apppasswords) — do NOT use your real account password.

This polls the inbox for unseen messages, saves each as a .eml file into
./incoming/, and (optionally) runs them straight through the analysis pipeline.
"""

import imaplib
import email
import os
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

IMAP_HOST = os.environ.get("IMAP_HOST", "")
IMAP_USER = os.environ.get("IMAP_USER", "")
IMAP_PASS = os.environ.get("IMAP_PASS", "")
INCOMING_DIR = "incoming"
POLL_INTERVAL_SECONDS = 30


def fetch_unseen_emails() -> list:
    """Connects to the IMAP server, fetches unseen emails, saves them as .eml,
    marks them as seen, and returns the list of saved file paths."""
    if not all([IMAP_HOST, IMAP_USER, IMAP_PASS]):
        raise EnvironmentError(
            "Set IMAP_HOST, IMAP_USER, and IMAP_PASS environment variables first. "
            "See the docstring at the top of this file for Gmail setup instructions."
        )

    os.makedirs(INCOMING_DIR, exist_ok=True)
    saved_files = []

    mail = imaplib.IMAP4_SSL(IMAP_HOST)
    mail.login(IMAP_USER, IMAP_PASS)
    mail.select("inbox")

    status, message_ids = mail.search(None, "UNSEEN")
    if status != "OK":
        mail.logout()
        return saved_files

    for msg_id in message_ids[0].split():
        status, msg_data = mail.fetch(msg_id, "(RFC822)")
        if status != "OK":
            continue
        raw_email = msg_data[0][1]

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(INCOMING_DIR, f"email_{timestamp}_{msg_id.decode()}.eml")
        with open(filename, "wb") as f:
            f.write(raw_email)
        saved_files.append(filename)
        print(f"Saved new email: {filename}")

    mail.logout()
    return saved_files


def poll_loop(on_new_email=None):
    """
    Continuously polls the inbox every POLL_INTERVAL_SECONDS.
    Pass a callback `on_new_email(file_path)` to automatically run each new
    email through the analysis pipeline (parse -> score -> store -> report).
    """
    print(f"Starting IMAP polling on {IMAP_HOST} every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")
    while True:
        try:
            new_files = fetch_unseen_emails()
            if on_new_email:
                for f in new_files:
                    on_new_email(f)
        except Exception as e:
            print(f"Polling error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    def _resolve_ingest_user_id() -> int:
        """save_case now requires a user_id (multi-tenant isolation). This standalone
        script isn't tied to a logged-in web session, so pick the owner explicitly:
        set IMAP_INGEST_USER_ID, or fall back to the admin account (ADMIN_EMAIL)."""
        configured = os.environ.get("IMAP_INGEST_USER_ID")
        if configured:
            return int(configured)

        from db import get_user_by_identifier
        from auth_config import ADMIN_EMAIL
        admin = get_user_by_identifier(ADMIN_EMAIL)
        if not admin:
            raise EnvironmentError(
                "No user_id configured for ingested cases. Either set IMAP_INGEST_USER_ID, "
                f"or sign up {ADMIN_EMAIL} through the app first so cases can default to the admin account."
            )
        return admin.id

    def run_pipeline(eml_path):
        from eml_parser import parse_eml
        from geoip_lookup import geolocate_ip
        from threat_intel import check_links
        from scoring import score_email
        from db import save_case

        parsed = parse_eml(eml_path)
        geo = geolocate_ip(parsed.get("originating_ip"))
        ti = check_links(parsed.get("links", []))
        verdict = score_email(parsed, geo, ti)
        case_id = save_case(parsed, geo, verdict, ti, filename=os.path.basename(eml_path),
                             user_id=_resolve_ingest_user_id())
        print(f"Case #{case_id}: {verdict['verdict']} (score {verdict['score']})")

    poll_loop(on_new_email=run_pipeline)
