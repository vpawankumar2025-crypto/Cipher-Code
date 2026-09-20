"""Shared test setup: put the project root on sys.path and give every test an
isolated SQLite database, so running the suite never touches a real one."""

import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Must be set before db.py is imported anywhere, since the engine is created at
# import time. Also neutralise outbound alerting for the whole suite.
_tmpdb = os.path.join(tempfile.gettempdir(), "sentinelmail_test.db")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmpdb}")
os.environ["ALERTS_ENABLED"] = "false"
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-not-a-real-key")


@pytest.fixture(scope="session")
def samples_dir():
    return os.path.join(ROOT, "samples")


@pytest.fixture(scope="session")
def phishing_eml(samples_dir):
    path = os.path.join(samples_dir, "phishing_email.eml")
    if not os.path.exists(path):
        pytest.skip("samples/phishing_email.eml not present")
    return path


@pytest.fixture(scope="session")
def clean_eml(samples_dir):
    path = os.path.join(samples_dir, "clean_email.eml")
    if not os.path.exists(path):
        pytest.skip("samples/clean_email.eml not present")
    return path


@pytest.fixture
def demo_case():
    """A case dict shaped exactly like db.get_case() returns."""
    return {
        "id": 1, "filename": "phishing_email.eml", "sender": "alert@fake-bank.com",
        "subject": "URGENT: verify your account",
        "received_date": "Mon, 1 Sep 2026 10:12:00 +0530",
        "originating_ip": "203.0.113.45", "spf_result": "fail", "dkim_result": "fail",
        "dmarc_result": "fail", "final_score": 88, "verdict": "Malicious",
        "analyst_override_verdict": None, "created_at": "2026-09-01T05:00:00",
        "threat_intel": {"malicious_count": 2},
        "parsed": {
            "from": '"Security" <alert@fake-bank.com>',
            "from_address": "alert@fake-bank.com", "to": "staff@college.edu.in",
            "subject": "URGENT: verify your account",
            "date": "Mon, 1 Sep 2026 10:12:00 +0530",
            "message_id": "<abc@fake-bank.com>", "attachments": [],
            "auth_results_raw": "spf=fail dkim=fail dmarc=fail", "received_chain": [],
        },
        "geo_full": {"city": "Amsterdam", "country": "Netherlands",
                     "isp": "Example Hosting BV", "lat": 52.37, "lon": 4.89},
        "typosquat": {"flagged": True, "matched_brand": "paypal.com", "distance": 1,
                     "technique": "hyphen/word insertion", "sender_label": "fake-bank"},
        "evidence_sha256": "48fc9a994c27131ea00600d967b1c22edc6c2914db0b3bddec1039dd8fbbe421",
        "evidence_hashed_at": "2026-09-01T05:00:00Z",
        "evidence_chain": [{"event": "ingested"}, {"event": "scored"}],
        "advanced": {
            "iocs": {"urls": ["http://fake-bank.com/verify"],
                     "domains": ["fake-bank.com"], "hashes": []},
            "header_forensics": {"from_domain": "fake-bank.com",
                                 "reply_to_domain": "mail.ru",
                                 "return_path_domain": "fake-bank.com",
                                 "received_hops": 3},
            "key_drivers": ["Authentication failure: SPF, DKIM, DMARC"],
            "attachment_analysis": {"risky": []},
        },
    }
