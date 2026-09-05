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
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text, DateTime, Boolean
)
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///sentinelmail_cases.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
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

    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()


def save_case(parsed: dict, geo: dict, verdict_data: dict, threat_intel: dict, filename: str) -> int:
    session = get_session()
    try:
        case = Case(
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
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        return case.id
    finally:
        session.close()


def list_cases(limit: int = 100) -> list:
    session = get_session()
    try:
        cases = session.query(Case).order_by(Case.created_at.desc()).limit(limit).all()
        return [_case_to_dict(c) for c in cases]
    finally:
        session.close()


def get_case(case_id: int) -> dict:
    session = get_session()
    try:
        case = session.query(Case).filter(Case.id == case_id).first()
        return _case_to_dict(case) if case else None
    finally:
        session.close()


def override_verdict(case_id: int, new_verdict: str, notes: str = "") -> bool:
    session = get_session()
    try:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return False
        case.analyst_override_verdict = new_verdict
        case.analyst_notes = notes
        case.reviewed = True
        session.commit()
        return True
    finally:
        session.close()


def dashboard_stats() -> dict:
    session = get_session()
    try:
        total = session.query(Case).count()
        malicious = session.query(Case).filter(Case.verdict == "Malicious").count()
        suspicious = session.query(Case).filter(Case.verdict == "Suspicious").count()
        safe = session.query(Case).filter(Case.verdict == "Safe").count()
        reviewed = session.query(Case).filter(Case.reviewed == True).count()  # noqa: E712
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
        "created_at": case.created_at.isoformat() if case.created_at else None,
    }


# Initialize tables on import
init_db()
