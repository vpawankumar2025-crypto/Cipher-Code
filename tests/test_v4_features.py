"""
Tests for the V4 additions: typosquat/lookalike-domain detection and
evidence-integrity hashing + chain-of-custody.
"""

import pytest


# --------------------- Typosquat detection ---------------------

def test_flags_the_projects_own_phishing_sample():
    """This is the exact sender domain in samples/phishing_email.eml —
    if this regresses, the headline demo claim breaks."""
    from typosquat import check_typosquat
    result = check_typosquat("paypa1-alerts.com")
    assert result["flagged"] is True
    assert result["matched_brand"] == "paypal.com"


def test_does_not_flag_the_real_brand_domain():
    from typosquat import check_typosquat
    assert check_typosquat("paypal.com")["flagged"] is False
    assert check_typosquat("hdfcbank.com")["flagged"] is False


def test_does_not_flag_unrelated_domains():
    from typosquat import check_typosquat
    result = check_typosquat("totally-unrelated-shop.example")
    assert result["flagged"] is False


def test_flags_hyphenated_brand_insertion():
    from typosquat import check_typosquat
    result = check_typosquat("secure.paypal-verify.com")
    assert result["flagged"] is True
    assert result["technique"] == "hyphen/word insertion"


def test_flags_homoglyph_substitution():
    from typosquat import check_typosquat
    result = check_typosquat("app1e.com")
    assert result["flagged"] is True
    assert result["matched_brand"] == "apple.com"
    assert result["technique"] == "homoglyph substitution"


def test_handles_empty_and_none_input_gracefully():
    from typosquat import check_typosquat
    assert check_typosquat("")["flagged"] is False
    assert check_typosquat(None)["flagged"] is False


def test_indian_bank_watchlist_entries_are_covered():
    from typosquat import check_typosquat
    result = check_typosquat("sbi-kyc-verify.online")
    assert result["flagged"] is True
    assert "sbi" in result["matched_brand"]


# --------------------- Evidence integrity ---------------------

def test_hash_is_deterministic_sha256():
    import hashlib
    from evidence_integrity import hash_evidence
    raw = b"From: a@b.com\nSubject: x\n\nbody"
    record = hash_evidence(raw, "test.eml")
    assert record["sha256"] == hashlib.sha256(raw).hexdigest()
    assert record["algorithm"] == "SHA-256"
    assert record["size_bytes"] == len(raw)


def test_verify_evidence_detects_tampering():
    from evidence_integrity import hash_evidence, verify_evidence
    raw = b"original bytes"
    record = hash_evidence(raw)
    assert verify_evidence(raw, record["sha256"]) is True
    assert verify_evidence(raw + b"tampered", record["sha256"]) is False
    assert verify_evidence(b"different bytes entirely", record["sha256"]) is False


def test_chain_links_correctly_and_verifies_intact():
    from evidence_integrity import append_chain, verify_chain
    e1 = append_chain("", "abc123", "ingested", "uploaded")
    e2 = append_chain(e1["chain_hash"], "abc123", "scored", "verdict=Malicious")
    e3 = append_chain(e2["chain_hash"], "abc123", "report_exported", "CERT-In PDF")
    chain = [e1, e2, e3]

    assert e2["prev_chain_hash"] == e1["chain_hash"]
    assert e3["prev_chain_hash"] == e2["chain_hash"]

    result = verify_chain(chain)
    assert result["valid"] is True
    assert result["entries_verified"] == 3


def test_chain_verification_catches_tampered_entry():
    from evidence_integrity import append_chain, verify_chain
    e1 = append_chain("", "abc123", "ingested", "uploaded")
    e2 = append_chain(e1["chain_hash"], "abc123", "scored", "verdict=Malicious score=88")
    e3 = append_chain(e2["chain_hash"], "abc123", "report_exported", "CERT-In PDF")

    tampered = [dict(e1), dict(e2), dict(e3)]
    tampered[1]["detail"] = "verdict=Safe score=5"  # attacker rewrites the verdict

    result = verify_chain(tampered)
    assert result["valid"] is False
    assert result["broken_at"] == 1


def test_chain_verification_catches_reordered_entries():
    from evidence_integrity import append_chain, verify_chain
    e1 = append_chain("", "abc123", "ingested", "uploaded")
    e2 = append_chain(e1["chain_hash"], "abc123", "scored", "verdict=Malicious")

    reordered = [e2, e1]  # swap order
    result = verify_chain(reordered)
    assert result["valid"] is False


def test_empty_chain_is_trivially_valid():
    from evidence_integrity import verify_chain
    result = verify_chain([])
    assert result["valid"] is True
    assert result["entries_verified"] == 0
