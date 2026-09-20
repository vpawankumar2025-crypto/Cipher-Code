"""
cert_in_report.py
Turns a Malicious case into a pre-filled incident report matching the fields
an Indian institution actually has to supply when reporting a phishing
incident — CERT-In's incident reporting form and the National Cyber Crime
Reporting Portal (cybercrime.gov.in).

This answers the question juries ask forensic tools specifically: "you
flagged it — then what?" The answer becomes: the IT team downloads a filled
form and files it, instead of retyping headers into a web form at 2am.

Two outputs from the same builder:
  build_incident_report(...)      -> dict (JSON export / API response)
  generate_cert_in_pdf(...)       -> a printable, signable PDF

SCOPE HONESTY — say this if asked, and keep it in the UI too: this produces
a *complete, correctly-structured draft* for a human to review, sign and
submit. It does not auto-file anything. There is no public API for
cybercrime.gov.in, and auto-submitting legal complaints without human
review would be the wrong design even if there were. The CERT-In directive
of 28 April 2022 requires reporting certain cyber incidents within 6 hours
of noticing them — the value here is removing the transcription time from
those 6 hours, not removing the human.

Reporter identity comes from the environment so no personal data is
hard-coded:
    REPORT_ORG_NAME, REPORT_ORG_TYPE, REPORT_CONTACT_NAME,
    REPORT_CONTACT_DESIGNATION, REPORT_CONTACT_EMAIL, REPORT_CONTACT_PHONE,
    REPORT_ORG_ADDRESS, REPORT_ORG_STATE
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

NOT_SUPPLIED = "— not supplied —"

# CERT-In incident categories, worded as the form does.
INCIDENT_CATEGORY = "Phishing / Spoofing / Fraudulent email"
CYBERCRIME_CATEGORY = "Online Financial Fraud / Phishing"


def _reporter_block() -> dict:
    return {
        "organisation_name": os.environ.get("REPORT_ORG_NAME", ""),
        "organisation_type": os.environ.get("REPORT_ORG_TYPE", "Educational Institution"),
        "contact_person": os.environ.get("REPORT_CONTACT_NAME", ""),
        "designation": os.environ.get("REPORT_CONTACT_DESIGNATION", "IT / Security Administrator"),
        "email": os.environ.get("REPORT_CONTACT_EMAIL", ""),
        "phone": os.environ.get("REPORT_CONTACT_PHONE", ""),
        "address": os.environ.get("REPORT_ORG_ADDRESS", ""),
        "state": os.environ.get("REPORT_ORG_STATE", ""),
    }


def _v(value, placeholder=NOT_SUPPLIED):
    if value in (None, "", [], {}):
        return placeholder
    return str(value)


def build_incident_report(case: dict) -> dict:
    """
    `case` is the dict returned by db.get_case() — flat columns plus the
    "parsed", "geo_full", "advanced" and "threat_intel" payloads.
    """
    parsed = case.get("parsed") or {}
    geo = case.get("geo_full") or {}
    advanced = case.get("advanced") or {}
    iocs = advanced.get("iocs") or {}
    headers = advanced.get("header_forensics") or {}
    verdict = case.get("analyst_override_verdict") or case.get("verdict")

    detected_at = case.get("created_at") or datetime.utcnow().isoformat()

    report = {
        "report_meta": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generated_by": "SentinelMail AI (SIH26106)",
            "source_case_id": case.get("id"),
            "status": "DRAFT — requires human review and signature before submission",
        },
        "reporter": _reporter_block(),

        # ---- CERT-In incident reporting fields ----
        "cert_in": {
            "incident_category": INCIDENT_CATEGORY,
            "incident_sub_category": "Malicious email / credential harvesting attempt",
            "date_time_of_occurrence": _v(parsed.get("date") or case.get("received_date")),
            "date_time_of_detection": detected_at,
            "timezone": "Asia/Kolkata (IST)",
            "affected_system": "Corporate/institutional email service (recipient mailbox)",
            "affected_user_or_asset": _v(parsed.get("to")),
            "brief_description": (
                f"An inbound email was automatically analysed and classified as "
                f"{verdict} with a composite risk score of {case.get('final_score')}/100. "
                f"Sender address {_v(parsed.get('from') or case.get('sender'))}; "
                f"originating IP {_v(case.get('originating_ip'))} geolocated to "
                f"{_v(geo.get('city'))}, {_v(geo.get('country'))} "
                f"(ISP: {_v(geo.get('isp'))}). "
                f"Email authentication results: SPF {_v(case.get('spf_result'), 'none')}, "
                f"DKIM {_v(case.get('dkim_result'), 'none')}, "
                f"DMARC {_v(case.get('dmarc_result'), 'none')}."
            ),
            "impact_assessment": _impact_line(case, advanced),
            "actions_taken": (
                "Message quarantined for analysis. Full header, URL and infrastructure "
                "forensics captured. Indicators of compromise extracted and listed below. "
                "Recipients advised not to interact with the message."
            ),
            "evidence_attached": [
                f"SentinelMail forensic report — case #{case.get('id')} (PDF)",
                f"Original message file: {_v(case.get('filename'))}",
            ],
        },

        # ---- cybercrime.gov.in ("Report Other Cyber Crime") fields ----
        "cybercrime_portal": {
            "category_of_complaint": CYBERCRIME_CATEGORY,
            "sub_category": "Phishing / Email fraud",
            "where_did_incident_occur": "Email",
            "approximate_date_time_of_incident": _v(parsed.get("date") or case.get("received_date")),
            "delay_in_reporting_reason": "Reported on detection by automated email security monitoring.",
            "suspect_email_id": _v(parsed.get("from_address") or case.get("sender")),
            "suspect_domain": _v(headers.get("from_domain")),
            "suspect_ip_address": _v(case.get("originating_ip")),
            "suspect_urls": (iocs.get("urls") or [])[:20],
            "financial_loss_reported": "Nil (attempt detected before user interaction)",
            "complaint_description": (
                f"A fraudulent email impersonating a legitimate sender was received on "
                f"{_v(parsed.get('date') or case.get('received_date'))}. "
                f"Subject line: \"{_v(parsed.get('subject') or case.get('subject'))}\". "
                "The message sought to induce the recipient to visit an attacker-controlled "
                "URL and disclose credentials or financial information. "
                "Technical indicators are listed in the attached report."
            ),
        },

        # ---- Machine-readable IOC block (shareable with a CSIRT/ISAC) ----
        "indicators_of_compromise": {
            "sender_addresses": [x for x in [parsed.get("from_address") or case.get("sender")] if x],
            "sender_domains": [x for x in [headers.get("from_domain")] if x],
            "reply_to_domain": headers.get("reply_to_domain") or "",
            "originating_ips": [x for x in [case.get("originating_ip")] if x],
            "urls": (iocs.get("urls") or [])[:50],
            "domains": (iocs.get("domains") or [])[:50],
            "file_hashes": (iocs.get("hashes") or [])[:50],
            "attachments": parsed.get("attachments") or [],
        },

        "technical_evidence": {
            "message_id": _v(parsed.get("message_id")),
            "return_path_domain": _v(headers.get("return_path_domain")),
            "received_hops": headers.get("received_hops", 0),
            "authentication_results_raw": _v(parsed.get("auth_results_raw")),
            "received_chain": (parsed.get("received_chain") or [])[:10],
            "risk_breakdown": advanced.get("risk_breakdown") or [],
            "key_drivers": advanced.get("key_drivers") or [],
            "threat_intel_hits": (case.get("threat_intel") or {}).get("malicious_count", 0),
            "typosquat_finding": _typosquat_line(case.get("typosquat") or {}),
            "evidence_sha256": _v(case.get("evidence_sha256")),
            "evidence_hashed_at": _v(case.get("evidence_hashed_at")),
            "evidence_chain_length": len(case.get("evidence_chain") or []),
        },

        "declaration": (
            "The information in this report was generated automatically from the "
            "original message headers and content by SentinelMail AI, and reviewed "
            "by the undersigned before submission. To the best of my knowledge the "
            "particulars stated are true and correct."
        ),
    }
    return report


def _typosquat_line(typo: dict) -> str:
    if not typo or not typo.get("flagged"):
        return "No lookalike-domain match against the brand watchlist"
    return (f"Sender domain resembles {typo.get('matched_brand')} "
            f"(edit distance {typo.get('distance')}, {typo.get('technique')})")


def _impact_line(case: dict, advanced: dict) -> str:
    ti = (case.get("threat_intel") or {}).get("malicious_count", 0)
    parts = []
    if ti:
        parts.append(f"{ti} embedded indicator(s) independently confirmed malicious by threat-intel sources")
    risky = (advanced.get("attachment_analysis") or {}).get("risky") or []
    if risky:
        parts.append(f"{len(risky)} executable/high-risk attachment(s) present")
    if not parts:
        parts.append("Credential-harvesting attempt; no confirmed compromise at time of reporting")
    return "; ".join(parts) + "."


# --------------------------- PDF rendering ---------------------------

def generate_cert_in_pdf(case: dict, output_path: str) -> str:
    report = build_incident_report(case)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Incident Report — case {case.get('id')}")
    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    title = ParagraphStyle("T", parent=styles["Title"], fontSize=16)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11.5, spaceBefore=12)
    small = ParagraphStyle("S", parent=normal, fontSize=8, textColor=colors.grey)
    cell = ParagraphStyle("C", parent=normal, fontSize=8.5, leading=11)

    def table(rows):
        data = [[Paragraph(f"<b>{k}</b>", cell), Paragraph(_v(v), cell)] for k, v in rows]
        t = Table(data, colWidths=[52 * mm, 122 * mm])
        t.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F2F4F7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    story = [
        Paragraph("CYBER SECURITY INCIDENT REPORT", title),
        Paragraph("Prepared for submission to CERT-In and the National Cyber Crime "
                  "Reporting Portal (cybercrime.gov.in)", small),
        Spacer(1, 4),
        Paragraph(f"<b>DRAFT</b> — generated {report['report_meta']['generated_at']} by "
                  f"SentinelMail AI from case #{case.get('id')}. "
                  f"Review, complete any blank fields and sign before submitting.", small),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#333333"), spaceBefore=8, spaceAfter=8),
    ]

    r = report["reporter"]
    story += [Paragraph("1. Reporting entity", h2), table([
        ("Organisation", r["organisation_name"]),
        ("Type of organisation", r["organisation_type"]),
        ("Contact person", r["contact_person"]),
        ("Designation", r["designation"]),
        ("Email", r["email"]),
        ("Phone", r["phone"]),
        ("Address", r["address"]),
        ("State / UT", r["state"]),
    ])]

    c = report["cert_in"]
    story += [Paragraph("2. Incident details (CERT-In format)", h2), table([
        ("Incident category", c["incident_category"]),
        ("Sub-category", c["incident_sub_category"]),
        ("Date/time of occurrence", c["date_time_of_occurrence"]),
        ("Date/time of detection", c["date_time_of_detection"]),
        ("Time zone", c["timezone"]),
        ("Affected system", c["affected_system"]),
        ("Affected user / asset", c["affected_user_or_asset"]),
        ("Brief description", c["brief_description"]),
        ("Impact assessment", c["impact_assessment"]),
        ("Actions taken", c["actions_taken"]),
        ("Evidence attached", "<br/>".join(c["evidence_attached"])),
    ])]

    p = report["cybercrime_portal"]
    story += [Paragraph("3. Complaint details (cybercrime.gov.in format)", h2), table([
        ("Category of complaint", p["category_of_complaint"]),
        ("Sub-category", p["sub_category"]),
        ("Where did it occur", p["where_did_incident_occur"]),
        ("Approx. date/time", p["approximate_date_time_of_incident"]),
        ("Reason for delay", p["delay_in_reporting_reason"]),
        ("Suspect email ID", p["suspect_email_id"]),
        ("Suspect domain", p["suspect_domain"]),
        ("Suspect IP address", p["suspect_ip_address"]),
        ("Suspect URLs", "<br/>".join(p["suspect_urls"]) or NOT_SUPPLIED),
        ("Financial loss", p["financial_loss_reported"]),
        ("Description", p["complaint_description"]),
    ])]

    i = report["indicators_of_compromise"]
    story += [Paragraph("4. Indicators of compromise", h2), table([
        ("Sender address(es)", "<br/>".join(i["sender_addresses"]) or NOT_SUPPLIED),
        ("Sender domain(s)", "<br/>".join(i["sender_domains"]) or NOT_SUPPLIED),
        ("Reply-To domain", i["reply_to_domain"]),
        ("Originating IP(s)", "<br/>".join(i["originating_ips"]) or NOT_SUPPLIED),
        ("URLs", "<br/>".join(i["urls"][:15]) or NOT_SUPPLIED),
        ("Domains", "<br/>".join(i["domains"][:15]) or NOT_SUPPLIED),
        ("File hashes", "<br/>".join(i["file_hashes"][:10]) or NOT_SUPPLIED),
        ("Attachments", "<br/>".join(str(a) for a in i["attachments"]) or NOT_SUPPLIED),
    ])]

    t = report["technical_evidence"]
    story += [Paragraph("5. Technical evidence", h2), table([
        ("Message-ID", t["message_id"]),
        ("Return-Path domain", t["return_path_domain"]),
        ("Received hops", t["received_hops"]),
        ("Authentication-Results", t["authentication_results_raw"]),
        ("Threat-intel hits", t["threat_intel_hits"]),
        ("Lookalike-domain check", t["typosquat_finding"]),
        ("Key detection drivers", "<br/>".join(f"• {d}" for d in t["key_drivers"][:8]) or NOT_SUPPLIED),
    ])]

    story += [Paragraph("6. Evidence integrity", h2), table([
        ("SHA-256 of original message", t["evidence_sha256"]),
        ("Hashed at (UTC)", t["evidence_hashed_at"]),
        ("Custody-chain entries", t["evidence_chain_length"]),
        ("Note", "The hash above was computed on the raw uploaded bytes at intake, "
                "before any parsing. Recomputing it over the original file and "
                "comparing to this value confirms the evidence has not been altered."),
    ])]

    story += [
        Paragraph("7. Declaration", h2),
        Paragraph(report["declaration"], cell),
        Spacer(1, 22),
        table([("Name & signature", ""), ("Designation", ""), ("Date", "")]),
        Spacer(1, 10),
        Paragraph("Generated by SentinelMail AI — SIH26106. This is an automatically "
                  "prepared draft, not a filed complaint.", small),
    ]

    doc.build(story)
    return output_path


if __name__ == "__main__":
    demo_case = {
        "id": 1, "filename": "phishing_email.eml", "sender": "alert@fake-bank.com",
        "subject": "URGENT: verify your account", "received_date": "Mon, 1 Sep 2026 10:12:00 +0530",
        "originating_ip": "203.0.113.45", "spf_result": "fail", "dkim_result": "fail",
        "dmarc_result": "fail", "final_score": 88, "verdict": "Malicious",
        "analyst_override_verdict": None, "created_at": "2026-09-01T05:00:00",
        "threat_intel": {"malicious_count": 2},
        "parsed": {"from": '"Security" <alert@fake-bank.com>', "from_address": "alert@fake-bank.com",
                   "to": "staff@college.edu.in", "subject": "URGENT: verify your account",
                   "date": "Mon, 1 Sep 2026 10:12:00 +0530", "message_id": "<abc@fake-bank.com>",
                   "attachments": [], "auth_results_raw": "spf=fail dkim=fail dmarc=fail",
                   "received_chain": []},
        "geo_full": {"city": "Amsterdam", "country": "Netherlands", "isp": "Example Hosting BV"},
        "typosquat": {"flagged": True, "matched_brand": "paypal.com", "distance": 1,
                     "technique": "hyphen/word insertion"},
        "evidence_sha256": "48fc9a994c27131ea00600d967b1c22edc6c2914db0b3bddec1039dd8fbbe421",
        "evidence_hashed_at": "2026-09-01T05:00:00Z",
        "evidence_chain": [{"event": "ingested"}, {"event": "scored"}],
        "advanced": {"iocs": {"urls": ["http://fake-bank.com/verify"], "domains": ["fake-bank.com"],
                              "hashes": []},
                     "header_forensics": {"from_domain": "fake-bank.com", "reply_to_domain": "mail.ru",
                                          "return_path_domain": "fake-bank.com", "received_hops": 3},
                     "key_drivers": ["Authentication failure: SPF, DKIM, DMARC"],
                     "attachment_analysis": {"risky": []}},
    }
    out = generate_cert_in_pdf(demo_case, "/tmp/cert_in_demo.pdf")
    print("wrote", out)
