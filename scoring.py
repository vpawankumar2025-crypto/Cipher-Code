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

from ml_classifier import predict_phishing_probability

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

    # --- Body content signals ---
    body = parsed.get("body_text", "").lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body]
    if hits:
        rule_score += min(len(hits) * 5, 20)
        reasons.append(f"Suspicious phrasing detected: {', '.join(hits[:5])}")

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

    rule_score = min(rule_score, 100)

    # --- Real ML model (content-based phishing probability) ---
    ml_probability = predict_phishing_probability(
        subject=parsed.get("subject", ""),
        body=parsed.get("body_text", ""),
        sender=parsed.get("from", ""),
    )
    ml_score = ml_probability * 100
    reasons.append(f"ML model phishing confidence: {ml_probability:.1%}")

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
    }
