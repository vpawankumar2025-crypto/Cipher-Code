"""
Tests for the parsing and scoring core.

Everything here runs offline: the two enrichment calls in scoring.py that hit
the network (WHOIS via domain_intel, the Tor exit-node list via infra_intel)
are monkeypatched. A test suite that only passes with internet access is not a
test suite a judge can run.
"""

import pytest

import eml_parser
import geoip_lookup


# --------------------------- parser ---------------------------

def test_parses_phishing_sample_headers(phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    assert parsed["from_address"] == "security@paypa1-alerts.com"
    assert parsed["display_name"] == "PayPal Security"
    assert parsed["subject"].startswith("URGENT")
    assert parsed["spf_result"] == "fail"
    assert parsed["dkim_result"] == "fail"
    assert parsed["dmarc_result"] == "fail"


def test_extracts_originating_ip_and_links(phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    assert parsed["originating_ip"] == "185.220.101.42"
    assert any("bit.ly" in link for link in parsed["links"])
    assert parsed["received_chain"], "Received chain should not be empty"


def test_reply_to_differs_from_from(phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    assert parsed["reply_to"] and parsed["from_address"] not in parsed["reply_to"]


def test_clean_sample_parses_without_auth_failures(clean_eml):
    parsed = eml_parser.parse_eml(clean_eml)
    assert parsed["from_address"]
    assert parsed["spf_result"] != "fail"


def test_private_ip_detection():
    assert eml_parser.is_private_ip("192.168.1.10") is True
    assert eml_parser.is_private_ip("10.0.0.1") is True
    assert eml_parser.is_private_ip("185.220.101.42") is False


# --------------------------- geoip ---------------------------

def test_geolocate_no_ip_is_graceful():
    """No IP must return a well-formed dict, never raise — the whole demo
    depends on this never blowing up mid-analysis."""
    result = geoip_lookup.geolocate_ip(None)
    assert result["status"] == "no_ip_found"
    assert result["country"] == "Unknown"
    assert result["lat"] is None


def test_geo_mismatch_needs_successful_lookup():
    assert geoip_lookup.check_geo_mismatch("India", {"status": "error"}) is False
    assert geoip_lookup.check_geo_mismatch("India", {"status": "success", "country": "Netherlands"}) is True
    assert geoip_lookup.check_geo_mismatch("India", {"status": "success", "country": "India"}) is False


# --------------------------- scoring ---------------------------

@pytest.fixture
def offline_scoring(monkeypatch):
    """Stub out the two network-dependent enrichments in scoring.py."""
    import scoring
    monkeypatch.setattr(scoring, "get_domain_intel",
                        lambda *a, **k: {"status": "skipped"})
    monkeypatch.setattr(scoring, "analyze_infrastructure",
                        lambda *a, **k: {"flags": [], "risk_contribution": 0})
    return scoring


def test_phishing_sample_scores_as_threat(offline_scoring, phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    geo = {"status": "success", "city": "Amsterdam", "country": "Netherlands",
           "isp": "Example Hosting BV"}
    result = offline_scoring.score_email(parsed, geo, {"malicious_count": 0})
    assert result["verdict"] in ("Suspicious", "Malicious")
    assert result["rule_score"] >= 40, "SPF+DKIM+DMARC failures alone should clear 40"
    assert 0.0 <= result["ml_probability"] <= 1.0
    assert any("SPF" in r for r in result["reasons"])
    # The sample's sender (paypa1-alerts.com) is a deliberate PayPal lookalike —
    # this is the concrete case the typosquat module exists to catch.
    assert result["typosquat"]["flagged"] is True
    assert result["typosquat"]["matched_brand"] == "paypal.com"


def test_threat_intel_hits_raise_the_score(offline_scoring, phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    geo = {"status": "success", "city": "X", "country": "Y", "isp": "Z"}
    without = offline_scoring.score_email(parsed, geo, {"malicious_count": 0})
    with_hits = offline_scoring.score_email(parsed, geo, {"malicious_count": 3})
    assert with_hits["rule_score"] > without["rule_score"]


def test_verdict_thresholds_are_consistent(offline_scoring, phishing_eml):
    parsed = eml_parser.parse_eml(phishing_eml)
    geo = {"status": "success", "city": "X", "country": "Y", "isp": "Z"}
    result = offline_scoring.score_email(parsed, geo, {"malicious_count": 0})
    score, verdict = result["score"], result["verdict"]
    expected = "Malicious" if score >= 60 else "Suspicious" if score >= 30 else "Safe"
    assert verdict == expected
    assert 0 <= score <= 100
