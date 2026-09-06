"""
db.py
Case storage layer using SQLAlchemy ORM.

Runs on SQLite by default (zero setup, works immediately for the demo).
To use real PostgreSQL as specified in the pitch deck, just set the
DATABASE_URL environment variable, e.g.:

    export DATABASE_URL="postgresql://user:password@localhost:5432/sentinelmail"

No code changes needed — SQLAlchemy handles both identically.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime, Boolean
)
from sqlalchemy.orm import declarative_base, sessionmaker

# as_posix() converts Windows backslashes to forward slashes — sqlite:/// URIs
# require forward slashes on every OS, so this keeps the DB path valid on Windows too.
_DEFAULT_DB_PATH = (Path(__file__).resolve().parent / "sentinelmail_cases.db").as_posix()
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)   # owner — every case belongs to exactly one user
    filename = Column(String, index=True)
    subject = Column(String)
    sender = Column(String)
    received_date = Column(String)

    originating_ip = Column(String)
    geo_country = Column(String)
    geo_city = Column(String)
    geo_isp = Column(String)

    spf_result = Column(String)
    dkim_result = Column(String)
    dmarc_result = Column(String)

    ml_phishing_probability = Column(Float, default=0.0)
    rule_based_score = Column(Integer, default=0)
    final_score = Column(Integer, default=0)
    verdict = Column(String, default="Safe")

    reasons_json = Column(Text)          # JSON-encoded list of evidence strings
    threat_intel_json = Column(Text)     # JSON-encoded threat intel results

    analyst_override_verdict = Column(String, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    reviewed = Column(Boolean, default=False)
    analyst_reviewed_at = Column(DateTime, nullable=True)

    # Full parsed-email / geolocation payloads, kept verbatim so nothing the
    # parser found (Reply-To, To, Message-ID, Received chain, links,
    # attachments, region, raw Authentication-Results, etc.) is lost between
    # analysis time and later report generation. body_text is stripped out
    # before storing (see save_case) since it's large and not needed downstream.
    parsed_json = Column(Text, nullable=True)
    geo_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    mobile = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String, nullable=True)       # null for Google-only accounts
    google_id = Column(String, unique=True, nullable=True)

    role = Column(String, default="user")                # "user" or "admin" — set via determine_role()

    email_verified = Column(Boolean, default=False)
    mobile_verified = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)          # true once all required channels are verified

    created_at = Column(DateTime, default=datetime.utcnow)


class OTP(Base):
    __tablename__ = "otps"

    id = Column(Integer, primary_key=True, index=True)
    identifier = Column(String, index=True)              # email or mobile the OTP was sent to
    channel = Column(String)                              # "email" or "sms"
    purpose = Column(String)                              # "signup" or "login"
    code_hash = Column(String)
    expires_at = Column(DateTime)
    consumed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ConnectedMailbox(Base):
    """A user's linked Gmail/Outlook account (OAuth), polled in the background
    so cases show up automatically without a manual .eml upload."""
    __tablename__ = "connected_mailboxes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    provider = Column(String, nullable=False)             # "google" or "microsoft"
    email_address = Column(String, nullable=False)

    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    token_expires_at = Column(DateTime, nullable=False)

    # Google: history sync uses timestamp-based polling (see mailbox_oauth.py) so
    # only last_synced_at is needed. Microsoft's raw-MIME fetch is also timestamp-driven.
    last_synced_at = Column(DateTime, nullable=True)

    status = Column(String, default="active")             # "active" or "error"
    last_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)


def _migrate_sqlite_schema():
    """create_all() only creates missing TABLES, it never ALTERs existing ones —
    so columns added to the Case model after the .db file already existed
    (parsed_json, geo_json, analyst_reviewed_at) need a manual ALTER TABLE on
    sqlite. No-op on Postgres/other backends or once columns already exist."""
    if not DATABASE_URL.startswith("sqlite"):
        return
    with engine.connect() as conn:
        existing = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(cases)")}
        for col_name, col_type in [
            ("parsed_json", "TEXT"),
            ("geo_json", "TEXT"),
            ("analyst_reviewed_at", "DATETIME"),
        ]:
            if col_name not in existing:
                conn.exec_driver_sql(f"ALTER TABLE cases ADD COLUMN {col_name} {col_type}")
        conn.commit()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_schema()


def get_session():
    return SessionLocal()


def case_exists(user_id: int, filename: str) -> bool:
    """Used by the mailbox poller to avoid re-inserting a message it already
    scored. `filename` for synced mail encodes provider:email:message_id, so
    it's a stable per-message key — unlike manual .eml uploads, where the same
    filename legitimately can recur, so this check is only used on the sync
    path, not for manual uploads."""
    session = get_session()
    try:
        return (
            session.query(Case.id)
            .filter(Case.user_id == user_id, Case.filename == filename)
            .first()
            is not None
        )
    finally:
        session.close()


def save_case(parsed: dict, geo: dict, verdict_data: dict, threat_intel: dict, filename: str, user_id: int) -> int:
    session = get_session()
    try:
        # Store the full parser/geo output (minus body_text, which is large and
        # not needed for the forensic report) so nothing is lost by the time a
        # report is generated later — Reply-To, To, Message-ID, Received chain,
        # raw Authentication-Results, links, attachments, region, etc.
        parsed_for_storage = {k: v for k, v in parsed.items() if k != "body_text"}

        case = Case(
            user_id=user_id,
            filename=filename,
            subject=parsed.get("subject", ""),
            sender=parsed.get("from", ""),
            received_date=parsed.get("date", ""),
            originating_ip=parsed.get("originating_ip"),
            geo_country=geo.get("country"),
            geo_city=geo.get("city"),
            geo_isp=geo.get("isp"),
            spf_result=parsed.get("spf_result"),
            dkim_result=parsed.get("dkim_result"),
            dmarc_result=parsed.get("dmarc_result"),
            ml_phishing_probability=verdict_data.get("ml_probability", 0.0),
            rule_based_score=verdict_data.get("rule_score", 0),
            final_score=verdict_data.get("score", 0),
            verdict=verdict_data.get("verdict", "Safe"),
            reasons_json=json.dumps(verdict_data.get("reasons", [])),
            threat_intel_json=json.dumps(threat_intel, default=str),
            parsed_json=json.dumps(parsed_for_storage, default=str),
            geo_json=json.dumps(geo, default=str),
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        return case.id
    finally:
        session.close()


def list_cases(user_id: int, is_admin: bool = False, limit: int = 100) -> list:
    session = get_session()
    try:
        query = session.query(Case)
        if not is_admin:
            query = query.filter(Case.user_id == user_id)
        cases = query.order_by(Case.created_at.desc()).limit(limit).all()
        return [_case_to_dict(c) for c in cases]
    finally:
        session.close()


def get_case(case_id: int, user_id: int, is_admin: bool = False) -> dict:
    session = get_session()
    try:
        query = session.query(Case).filter(Case.id == case_id)
        if not is_admin:
            query = query.filter(Case.user_id == user_id)
        case = query.first()
        return _case_to_dict(case) if case else None
    finally:
        session.close()


def override_verdict(case_id: int, new_verdict: str, user_id: int, is_admin: bool = False, notes: str = "") -> bool:
    session = get_session()
    try:
        query = session.query(Case).filter(Case.id == case_id)
        if not is_admin:
            query = query.filter(Case.user_id == user_id)
        case = query.first()
        if not case:
            return False
        case.analyst_override_verdict = new_verdict
        case.analyst_notes = notes
        case.reviewed = True
        case.analyst_reviewed_at = datetime.utcnow()
        session.commit()
        return True
    finally:
        session.close()


def dashboard_stats(user_id: int, is_admin: bool = False) -> dict:
    session = get_session()
    try:
        base = session.query(Case)
        if not is_admin:
            base = base.filter(Case.user_id == user_id)
        total = base.count()
        malicious = base.filter(Case.verdict == "Malicious").count()
        suspicious = base.filter(Case.verdict == "Suspicious").count()
        safe = base.filter(Case.verdict == "Safe").count()
        reviewed = base.filter(Case.reviewed == True).count()  # noqa: E712
        return {
            "total_cases": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "safe": safe,
            "reviewed": reviewed,
            "pending_review": total - reviewed,
        }
    finally:
        session.close()


def _case_to_dict(case: Case) -> dict:
    return {
        "id": case.id,
        "user_id": case.user_id,
        "filename": case.filename,
        "subject": case.subject,
        "sender": case.sender,
        "received_date": case.received_date,
        "originating_ip": case.originating_ip,
        "geo_country": case.geo_country,
        "geo_city": case.geo_city,
        "geo_isp": case.geo_isp,
        "spf_result": case.spf_result,
        "dkim_result": case.dkim_result,
        "dmarc_result": case.dmarc_result,
        "ml_phishing_probability": case.ml_phishing_probability,
        "rule_based_score": case.rule_based_score,
        "final_score": case.final_score,
        "verdict": case.verdict,
        "reasons": json.loads(case.reasons_json) if case.reasons_json else [],
        "threat_intel": json.loads(case.threat_intel_json) if case.threat_intel_json else {},
        "analyst_override_verdict": case.analyst_override_verdict,
        "analyst_notes": case.analyst_notes,
        "reviewed": case.reviewed,
        "analyst_reviewed_at": case.analyst_reviewed_at.isoformat() if case.analyst_reviewed_at else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        # Full payloads for report generation — empty dict for rows saved
        # before these columns existed, so older cases degrade gracefully
        # instead of erroring.
        "parsed": json.loads(case.parsed_json) if case.parsed_json else {},
        "geo_full": json.loads(case.geo_json) if case.geo_json else {},
    }


from auth_config import determine_role


def get_user_by_identifier(identifier: str):
    session = get_session()
    try:
        return session.query(User).filter(
            (User.username == identifier) |
            (User.email == identifier.lower()) |
            (User.mobile == identifier)
        ).first()
    finally:
        session.close()


def create_user(username: str, email: str, mobile: str = None, password_hash: str = None,
                 google_id: str = None) -> "User":
    session = get_session()
    try:
        user = User(
            username=username,
            email=email.strip().lower(),
            mobile=mobile,
            password_hash=password_hash,
            google_id=google_id,
            role=determine_role(email),      # role by email match, not signup order
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


def mark_channel_verified(user_id: int, channel: str):
    """channel is 'email' or 'sms'. Marks that channel verified, and flips is_verified
    to True once every channel the account actually has is verified (mobile is optional
    for Google-only accounts, so it's not required there)."""
    session = get_session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            return
        if channel == "email":
            user.email_verified = True
        elif channel == "sms":
            user.mobile_verified = True

        email_ok = user.email_verified
        mobile_ok = user.mobile_verified or not user.mobile  # not required if no mobile on file
        user.is_verified = email_ok and mobile_ok
        session.commit()
    finally:
        session.close()


def set_fully_verified(user_id: int):
    """Used for Google logins — Google already verified the email, and there's no mobile to check."""
    session = get_session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            user.email_verified = True
            user.is_verified = True
            session.commit()
    finally:
        session.close()


# Initialize tables on import
init_db()


# ---------------- Connected mailboxes ----------------

def upsert_mailbox(user_id: int, provider: str, email_address: str, access_token: str,
                    refresh_token: str, token_expires_at: datetime) -> int:
    """Creates the connection, or refreshes tokens on an existing one if this
    user already connected this exact provider+email combo before."""
    session = get_session()
    try:
        existing = (
            session.query(ConnectedMailbox)
            .filter(
                ConnectedMailbox.user_id == user_id,
                ConnectedMailbox.provider == provider,
                ConnectedMailbox.email_address == email_address,
            )
            .first()
        )
        if existing:
            existing.access_token = access_token
            existing.refresh_token = refresh_token
            existing.token_expires_at = token_expires_at
            existing.status = "active"
            existing.last_error = None
            session.commit()
            return existing.id

        mailbox = ConnectedMailbox(
            user_id=user_id,
            provider=provider,
            email_address=email_address,
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at,
        )
        session.add(mailbox)
        session.commit()
        session.refresh(mailbox)
        return mailbox.id
    finally:
        session.close()


def list_mailboxes_for_user(user_id: int) -> list:
    session = get_session()
    try:
        rows = session.query(ConnectedMailbox).filter(ConnectedMailbox.user_id == user_id).all()
        return [_mailbox_to_dict(m) for m in rows]
    finally:
        session.close()


def get_mailbox(mailbox_id: int, user_id: int = None):
    """Returns the ORM row (not a dict) — callers that update tokens/sync state need this."""
    session = get_session()
    try:
        query = session.query(ConnectedMailbox).filter(ConnectedMailbox.id == mailbox_id)
        if user_id is not None:
            query = query.filter(ConnectedMailbox.user_id == user_id)
        return query.first()
    finally:
        session.close()


def all_active_mailboxes() -> list:
    """Used by the background poller — every connected account across every user."""
    session = get_session()
    try:
        return session.query(ConnectedMailbox).filter(ConnectedMailbox.status == "active").all()
    finally:
        session.close()


def update_mailbox_tokens(mailbox_id: int, access_token: str, token_expires_at: datetime):
    session = get_session()
    try:
        m = session.query(ConnectedMailbox).filter(ConnectedMailbox.id == mailbox_id).first()
        if m:
            m.access_token = access_token
            m.token_expires_at = token_expires_at
            session.commit()
    finally:
        session.close()


def update_mailbox_sync_state(mailbox_id: int, synced_at: datetime, error: str = None):
    session = get_session()
    try:
        m = session.query(ConnectedMailbox).filter(ConnectedMailbox.id == mailbox_id).first()
        if not m:
            return
        if error:
            m.status = "error"
            m.last_error = error
            # Still record how far this cycle got (paired with the
            # case_exists() skip in mailbox_poller) so a retry after the
            # underlying error clears doesn't re-walk messages already saved.
            if synced_at:
                m.last_synced_at = synced_at
        else:
            m.status = "active"
            m.last_error = None
            m.last_synced_at = synced_at
        session.commit()
    finally:
        session.close()


def delete_mailbox(mailbox_id: int, user_id: int) -> bool:
    session = get_session()
    try:
        m = (
            session.query(ConnectedMailbox)
            .filter(ConnectedMailbox.id == mailbox_id, ConnectedMailbox.user_id == user_id)
            .first()
        )
        if not m:
            return False
        session.delete(m)
        session.commit()
        return True
    finally:
        session.close()


def _mailbox_to_dict(m: ConnectedMailbox) -> dict:
    return {
        "id": m.id,
        "provider": m.provider,
        "email_address": m.email_address,
        "status": m.status,
        "last_error": m.last_error,
        "last_synced_at": m.last_synced_at.isoformat() if m.last_synced_at else None,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }
