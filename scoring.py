"""
scoring.py
Combined threat scoring engine:
- Real ML model (ml_classifier.py, TF-IDF + Logistic Regression) provides a
  phishing probability from email content.
- Rule-based checklist adds authentication/header/link signals the ML model
  doesn't see directly (SPF/DKIM/DMARC, display-name spoofing, attachments).
- Threat-intel hits (VirusTotal/PhishTank) add further weight if links are
  independently confirmed malicious.

Final score blends all three into one 0-100 risk score -> verdict.
"""

from language_router import (
    predict_phishing_probability_multilingual,
    regional_keyword_score,
)
from ml_explain import explain_prediction
from domain_intel import get_domain_intel
from infra_intel import analyze_infrastructure
from typosquat import check_typosquat

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "suspended", "click here", "act now",
    "confirm your password", "bank details", "wire transfer", "gift card",
    "limited time", "your account will be closed", "unusual activity",
    "otp", "one time password", "kyc update",
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]


def score_email(parsed: dict, geo: dict, threat_intel_result: dict = None) -> dict:
    threat_intel_result = threat_intel_result or {}
    threat_intel_hits = threat_intel_result.get("malicious_count", 0)

    rule_score = 0
    reasons = []

    # --- Authentication checks ---
    if parsed.get("spf_result") == "fail":
        rule_score += 20
        reasons.append("SPF check failed — sending server not authorized for this domain")
    elif parsed.get("spf_result") == "none":
        rule_score += 8
        reasons.append("No SPF record found / not evaluated")

    if parsed.get("dkim_result") == "fail":
        rule_score += 20
        reasons.append("DKIM signature invalid or missing")
    elif parsed.get("dkim_result") == "none":
        rule_score += 8
        reasons.append("No DKIM signature present")

    if parsed.get("dmarc_result") == "fail":
        rule_score += 20
        reasons.append("DMARC alignment failed")

    # --- Display name / address mismatch ---
    display_name = parsed.get("display_name", "")
    from_address = parsed.get("from_address", "")
    if display_name and "@" in display_name:
        rule_score += 15
        reasons.append("Display name itself contains an email address (spoofing pattern)")

    reply_to = parsed.get("reply_to", "")
    if reply_to and from_address and reply_to.strip() != "" and from_address not in reply_to:
        rule_score += 10
        reasons.append(f"Reply-To ({reply_to}) differs from From address — common redirect tactic")

    # --- Lookalike / typosquatted sender domain ---
    sender_domain = from_address.split("@")[-1] if "@" in from_address else from_address
    typo_result = check_typosquat(sender_domain)
    if typo_result.get("flagged"):
        rule_score += 25
        reasons.append(
            f"Sender domain '{sender_domain}' closely resembles '{typo_result['matched_brand']}' "
            f"(edit distance {typo_result['distance']}, {typo_result['technique']}) — likely "
            f"brand impersonation / typosquatting"
        )

    # --- Body content signals ---
    body = parsed.get("body_text", "").lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body]
    if hits:
        rule_score += min(len(hits) * 5, 20)
        reasons.append(f"Suspicious phrasing detected: {', '.join(hits[:5])}")

    # --- Regional-language fraud vocabulary (Hindi / romanized Hinglish) ---
    # Script-independent, so it fires on both "केवाईसी सत्यापित करें" and
    # "KYC verify karein". Runs regardless of which model scores the email.
    regional = regional_keyword_score(
        (parsed.get("subject", "") or "") + "\n" + (parsed.get("body_text", "") or "")
    )
    if regional["score"]:
        rule_score += regional["score"]
        reasons.append(
            "Hindi/Hinglish fraud vocabulary detected: " + ", ".join(regional["hits"])
        )

    # --- Links ---
    links = parsed.get("links", [])
    shortened = [l for l in links if any(s in l for s in SHORTENER_DOMAINS)]
    if shortened:
        rule_score += 10
        reasons.append(f"Shortened/obfuscated URL(s) found: {len(shortened)}")

    # --- Attachments ---
    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".jar")
    risky_attachments = [a for a in parsed.get("attachments", []) if a.lower().endswith(risky_ext)]
    if risky_attachments:
        rule_score += 20
        reasons.append(f"Potentially dangerous attachment type(s): {risky_attachments}")

    # --- Threat intel (VirusTotal / PhishTank hits, passed in) ---
    if threat_intel_hits > 0:
        rule_score += 25
        reasons.append(f"{threat_intel_hits} link(s)/attachment(s) flagged by threat-intel sources")

    # --- Geo signal ---
    if geo.get("status") == "success":
        reasons.append(f"Sender IP geolocated to {geo.get('city')}, {geo.get('country')} (ISP: {geo.get('isp')})")
    elif geo.get("status") in ("no_ip_found",):
        rule_score += 5
        reasons.append("Could not determine originating IP from headers — reduces traceability")

    # --- Infrastructure correlation: VPN/Tor/cloud-hosting indicators ---
    infra = analyze_infrastructure(parsed.get("originating_ip"), geo)
    if infra["flags"]:
        rule_score += infra["risk_contribution"]
        reasons.extend(infra["flags"])

    # --- Domain-registration intelligence (WHOIS) ---
    domain_info = get_domain_intel(parsed.get("from_address") or parsed.get("from", ""))
    if domain_info.get("status") == "success":
        if domain_info.get("recently_registered"):
            rule_score += 20
            reasons.append(
                f"Sender domain '{domain_info['domain']}' was registered only "
                f"{domain_info['age_days']} day(s) ago — recently-registered domains "
                f"are a strong phishing/impersonation indicator"
            )
        else:
            reasons.append(
                f"Sender domain '{domain_info['domain']}' registered ~{domain_info['age_days']} days ago "
                f"via {domain_info.get('registrar') or 'unknown registrar'}"
            )

    rule_score = min(rule_score, 100)

    # --- Real ML model (content-based phishing probability) ---
    ml_result = predict_phishing_probability_multilingual(
        subject=parsed.get("subject", ""),
        body=parsed.get("body_text", ""),
        sender=parsed.get("from", ""),
    )
    ml_probability = ml_result["probability"]
    ml_score = ml_probability * 100
    reasons.append(
        f"ML model phishing confidence: {ml_probability:.1%} "
        f"(language: {ml_result['language']}, model: {ml_result['model_used']})"
    )
    if ml_result["language"] != "en":
        reasons.append(
            f"Email detected as {ml_result['language']} — routed to the "
            f"regional-language classifier"
        )

    # Term-level attribution. The English model is word-level TF-IDF, so its
    # features are readable words. The Hindi model is character n-gram based
    # (spelling varies too much in romanized Hinglish for word features), and
    # character 4-grams mean nothing to a human — so for regional mail the
    # explanation is the keyword layer's hits instead. Never show char n-grams
    # to a jury and call them an explanation.
    if ml_result["model_used"] == "english":
        ml_explanation = explain_prediction(
            subject=parsed.get("subject", ""),
            body=parsed.get("body_text", ""),
            sender=parsed.get("from", ""),
        )
    else:
        ml_explanation = {
            "available": True,
            "phishing_terms": [{"term": h, "contribution": None, "share_pct": None}
                               for h in regional["hits"]],
            "safe_terms": [],
            "sentence": ("Flagged by the regional-language classifier; matched fraud "
                         "vocabulary: " + ", ".join(regional["hits"])
                         if regional["hits"] else
                         "Scored by the regional-language classifier."),
            "note": "Character-level model — term attribution shown from the keyword layer.",
        }

    # --- Blend: 55% ML content model, 45% rule-based header/link/threat-intel signals ---
    final_score = round(0.55 * ml_score + 0.45 * rule_score)
    final_score = min(final_score, 100)

    if final_score >= 60:
        verdict = "Malicious"
    elif final_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "score": final_score,
        "rule_score": rule_score,
        "ml_probability": round(ml_probability, 3),
        "verdict": verdict,
        "reasons": reasons,
        "infra_intel": infra,
        "domain_intel": domain_info,
        "language": ml_result["language"],
        "language_confidence": ml_result["language_confidence"],
        "model_used": ml_result["model_used"],
        "ml_explanation": ml_explanation,
        "typosquat": typo_result,
    }
