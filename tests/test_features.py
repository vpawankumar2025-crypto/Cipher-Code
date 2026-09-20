"""
Tests for the V3 additions: ML explainability, language routing, alert
gating and the CERT-In export.
"""

import math
import os

import pytest


# --------------------- ML explainability ---------------------

def test_explanation_reconstructs_the_models_own_decision():
    """The headline claim: term contributions + intercept == the model's raw
    log-odds, so the explanation is arithmetic, not an approximation. If this
    test fails, the explainability feature must not be described as exact."""
    from ml_classifier import predict_phishing_probability
    from ml_explain import explain_prediction

    subject = "URGENT: verify your account now"
    body = ("Click here to confirm your password and bank details immediately "
            "or your account will be suspended.")
    sender = '"Security Team" <alert@fake-bank.com>'

    prob = predict_phishing_probability(subject, body, sender)
    explanation = explain_prediction(subject, body, sender)

    assert explanation["available"] is True
    reconstructed = 1 / (1 + math.exp(-explanation["decision_value"]))
    assert reconstructed == pytest.approx(prob, abs=1e-4)


def test_explanation_surfaces_phishing_vocabulary():
    from ml_explain import explain_prediction
    explanation = explain_prediction(
        "Verify your account",
        "Click here to confirm your bank details immediately.",
        "alert@fake-bank.com",
    )
    terms = {t["term"] for t in explanation["phishing_terms"]}
    assert terms & {"account", "bank", "click", "verify", "confirm"}
    assert explanation["sentence"]
    assert all(0 <= t["share_pct"] <= 100 for t in explanation["phishing_terms"])


def test_highlight_spans_point_at_real_offsets():
    from ml_explain import highlight_spans
    body = "Please verify your account immediately."
    spans = highlight_spans(body, [{"term": "verify", "share_pct": 20.0}])
    assert spans and body[spans[0]["start"]:spans[0]["end"]].lower() == "verify"


# --------------------- Language routing ---------------------

def test_detects_devanagari_hindi():
    from language_router import detect_language
    result = detect_language("प्रिय ग्राहक, आपका बैंक खाता बंद कर दिया जाएगा। तुरंत सत्यापित करें।")
    assert result["language"] == "hi"
    assert result["devanagari_ratio"] > 0.5


def test_detects_romanized_hinglish():
    from language_router import detect_language
    result = detect_language("Dear customer, aapka bank khata turant band ho jayega. "
                             "Kripya KYC update karein.")
    assert result["language"] == "hi-en"
    assert result["markers"]


def test_plain_english_is_not_misrouted():
    from language_router import detect_language
    result = detect_language("Hi team, attaching the agenda for tomorrow's planning "
                             "meeting. Please review the quarterly numbers.")
    assert result["language"] == "en"


def test_regional_keyword_layer_fires_in_both_scripts():
    from language_router import regional_keyword_score
    hindi = regional_keyword_score("कृपया तुरंत केवाईसी सत्यापित करें, खाता बंद हो जाएगा")
    hinglish = regional_keyword_score("turant KYC update karein warna account band")
    english = regional_keyword_score("Please find the meeting notes attached.")
    assert hindi["score"] > 0 and hindi["hits"]
    assert hinglish["score"] > 0 and hinglish["hits"]
    assert english["score"] == 0


def test_multilingual_router_returns_a_usable_probability():
    from language_router import predict_phishing_probability_multilingual
    result = predict_phishing_probability_multilingual(
        "KYC update karein turant",
        "Aapka khata band ho jayega. Kripya is link par click karein.",
        "kyc@bank-update.top",
    )
    assert 0.0 <= result["probability"] <= 1.0
    assert result["language"] in ("hi", "hi-en")
    assert result["model_used"] in ("hindi", "english")   # degrades safely if untrained


# --------------------- Alerting ---------------------

def test_safe_verdicts_never_alert(monkeypatch):
    import alerts
    monkeypatch.setattr(alerts, "ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts, "ALERT_EMAIL_TO", "soc@example.org")
    result = alerts.maybe_alert(1, {"verdict": "Safe", "score": 12},
                                {"from": "a@b.com"}, {}, user_id=1)
    assert result["alerted"] is False
    assert result["reason"] == "below_threshold"


def test_alerting_is_disabled_without_a_recipient(monkeypatch):
    import alerts
    monkeypatch.setattr(alerts, "ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts, "ALERT_EMAIL_TO", "")
    monkeypatch.setattr(alerts, "ALERT_SMS_TO", "")
    result = alerts.maybe_alert(1, {"verdict": "Malicious", "score": 90},
                                {"from": "a@b.com"}, {}, user_id=1)
    assert result["alerted"] is False
    assert result["reason"] == "no_recipient_configured"


def test_campaign_deduplication_suppresses_the_second_alert(monkeypatch):
    """One campaign hitting many mailboxes must not fan out into many SMS."""
    import alerts
    monkeypatch.setattr(alerts, "ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts, "ALERT_EMAIL_TO", "soc@example.org")
    monkeypatch.setattr(alerts, "ALERT_SMS_TO", "")
    monkeypatch.setattr(alerts, "_deliver", lambda *a, **k: None)
    alerts._last_sent.clear()

    verdict = {"verdict": "Malicious", "score": 91}
    parsed = {"from": "attacker@evil-domain.test", "subject": "x"}
    first = alerts.maybe_alert(1, verdict, parsed, {}, user_id=1)
    second = alerts.maybe_alert(2, verdict, dict(parsed, **{"from": "other@evil-domain.test"}),
                                {}, user_id=1)
    assert first["alerted"] is True
    assert second["alerted"] is False
    assert second["reason"] == "suppressed_duplicate_campaign"


# --------------------- CERT-In export ---------------------

def test_incident_report_has_every_required_section(demo_case):
    from cert_in_report import build_incident_report
    report = build_incident_report(demo_case)
    for section in ("report_meta", "reporter", "cert_in", "cybercrime_portal",
                    "indicators_of_compromise", "technical_evidence", "declaration"):
        assert section in report


def test_incident_report_carries_the_case_iocs(demo_case):
    from cert_in_report import build_incident_report
    report = build_incident_report(demo_case)
    iocs = report["indicators_of_compromise"]
    assert "203.0.113.45" in iocs["originating_ips"]
    assert "fake-bank.com" in iocs["sender_domains"]
    assert report["cybercrime_portal"]["suspect_ip_address"] == "203.0.113.45"


def test_report_is_marked_as_a_draft(demo_case):
    """It must never present itself as a filed complaint."""
    from cert_in_report import build_incident_report
    report = build_incident_report(demo_case)
    assert "DRAFT" in report["report_meta"]["status"].upper()


def test_cert_in_pdf_is_written(tmp_path, demo_case):
    from cert_in_report import generate_cert_in_pdf
    out = tmp_path / "incident.pdf"
    generate_cert_in_pdf(demo_case, str(out))
    assert out.exists() and out.stat().st_size > 1500
    assert out.read_bytes()[:4] == b"%PDF"


# --------------------- Attack map aggregation ---------------------

def test_attack_map_skips_cases_without_coordinates():
    """Guard against the map silently plotting (0, 0) — 'Null Island' pins are
    the classic geo-dashboard bug and look terrible on a projector."""
    pytest.importorskip("sqlalchemy")
    import db
    points = db._points_from_cases([
        {"id": 1, "geo_full": {"lat": 52.3, "lon": 4.9, "country": "NL", "city": "Amsterdam"},
         "verdict": "Malicious", "final_score": 90, "sender": "a@b.com",
         "originating_ip": "1.2.3.4", "subject": "x", "created_at": None,
         "analyst_override_verdict": None},
        {"id": 2, "geo_full": {}, "verdict": "Safe", "final_score": 5, "sender": "c@d.com",
         "originating_ip": None, "subject": "y", "created_at": None,
         "analyst_override_verdict": None},
    ])
    assert len(points) == 1
    assert points[0]["lat"] == 52.3
