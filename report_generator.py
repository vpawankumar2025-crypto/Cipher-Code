"""
report_generator.py
Generates a forensic-grade PDF report summarizing the email analysis:
verdict, score breakdown, authentication results, geolocation, links,
attachments, raw header chain, and any analyst review/override.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime


VERDICT_COLORS = {
    "Safe": colors.HexColor("#2e7d32"),
    "Suspicious": colors.HexColor("#f9a825"),
    "Malicious": colors.HexColor("#c62828"),
}

NOT_PRESENT = "Not present in email headers"
UNKNOWN = "Unknown / not determined"


def _fmt(value, placeholder=NOT_PRESENT):
    """Render a value for the PDF, with an honest placeholder instead of a
    blank cell when the field genuinely wasn't found — so 'empty' always
    means 'we looked and it wasn't there', never 'we forgot to fetch it'."""
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return placeholder
    return str(value)


def _fmt_dt(value):
    if not value:
        return UNKNOWN
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_report(parsed: dict, geo: dict, verdict_data: dict, output_path: str, case_meta: dict = None):
    case_meta = case_meta or {}
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], spaceBefore=14)
    small_grey = ParagraphStyle("SmallGrey", parent=styles["Normal"], fontSize=8, textColor=colors.grey)
    normal = styles["Normal"]
    mono_small = ParagraphStyle("MonoSmall", parent=styles["Normal"], fontName="Courier", fontSize=7.5, leading=10)

    verdict_color = VERDICT_COLORS.get(verdict_data["verdict"], colors.black)
    verdict_style = ParagraphStyle(
        "Verdict", parent=styles["Heading1"], textColor=verdict_color, fontSize=22
    )

    def grid_table(data, col_widths, header_row=False, key_col_shade=True):
        style_cmds = [
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]
        if header_row:
            style_cmds += [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        elif key_col_shade:
            style_cmds.append(("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")))
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle(style_cmds))
        return t

    # Wrap long cell text in Paragraphs so it wraps instead of overflowing.
    def p(text, style=normal):
        return Paragraph(_fmt(text) if not isinstance(text, str) else (text or NOT_PRESENT), style)

    elements = []

    elements.append(Paragraph("SentinelMail AI — Forensic Analysis Report", title_style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
    if case_meta.get("case_id") is not None:
        elements.append(Paragraph(
            f"Case ID: {case_meta['case_id']}    |    Source file: {_fmt(case_meta.get('filename'))}    |    "
            f"Analyzed: {_fmt_dt(case_meta.get('analyzed_at'))}",
            small_grey
        ))
    elements.append(HRFlowable(width="100%", color=colors.grey, spaceBefore=10, spaceAfter=10))

    # --- Verdict block ---
    engine_verdict = verdict_data.get("engine_verdict", verdict_data["verdict"])
    override_verdict = case_meta.get("analyst_override_verdict")
    elements.append(Paragraph(f"Verdict: {verdict_data['verdict']}", verdict_style))
    if override_verdict and override_verdict != engine_verdict:
        elements.append(Paragraph(
            f"(Automated engine verdict was \u201c{engine_verdict}\u201d — an analyst overrode this to "
            f"\u201c{override_verdict}\u201d; see Analyst Review below.)", small_grey))
    elements.append(Paragraph(f"Risk Score: {verdict_data['score']} / 100", normal))
    elements.append(Spacer(1, 10))

    # --- Score breakdown ---
    elements.append(Paragraph("Risk Score Breakdown", heading_style))
    ml_prob = verdict_data.get("ml_probability")
    rule_score = verdict_data.get("rule_score")
    breakdown_data = [
        ["Component", "Value", "Weight in final score"],
        ["ML content-model phishing confidence",
         f"{ml_prob:.1%}" if isinstance(ml_prob, (int, float)) else UNKNOWN, "55%"],
        ["Rule-based header/link/attachment score",
         f"{rule_score} / 100" if rule_score is not None else UNKNOWN, "45%"],
        ["Final blended risk score", f"{verdict_data['score']} / 100", "—"],
    ]
    elements.append(grid_table(breakdown_data, [8 * cm, 4 * cm, 3.5 * cm], header_row=True))
    elements.append(Paragraph(
        "Verdict thresholds: score < 30 = Safe, 30–59 = Suspicious, \u2265 60 = Malicious.",
        small_grey))
    elements.append(Spacer(1, 12))

    # --- Email metadata table ---
    elements.append(Paragraph("Email Metadata", heading_style))
    meta_table_data = [
        ["From", p(parsed.get("from"))],
        ["Display Name", p(parsed.get("display_name"))],
        ["From Address", p(parsed.get("from_address"))],
        ["Reply-To", p(parsed.get("reply_to"))],
        ["To", p(parsed.get("to"))],
        ["Subject", p(parsed.get("subject"))],
        ["Date", p(parsed.get("date"))],
        ["Message-ID", p(parsed.get("message_id"))],
    ]
    elements.append(grid_table(meta_table_data, [3.5 * cm, 12 * cm]))
    elements.append(Spacer(1, 12))

    # --- Authentication results ---
    elements.append(Paragraph("Email Authentication Results", heading_style))
    auth_table_data = [
        ["Mechanism", "Result"],
        ["SPF", _fmt(parsed.get("spf_result"), "none")],
        ["DKIM", _fmt(parsed.get("dkim_result"), "none")],
        ["DMARC", _fmt(parsed.get("dmarc_result"), "none")],
    ]
    elements.append(grid_table(auth_table_data, [6 * cm, 6 * cm], header_row=True))
    if parsed.get("auth_results_raw"):
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("Raw Authentication-Results header:", small_grey))
        elements.append(Paragraph(parsed["auth_results_raw"], mono_small))
    elements.append(Spacer(1, 12))

    # --- Geolocation ---
    elements.append(Paragraph("Sender IP & Geolocation", heading_style))
    lat, lon = geo.get("lat"), geo.get("lon")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else UNKNOWN
    geo_table_data = [
        ["Originating IP", _fmt(parsed.get("originating_ip"), "Not determined from Received headers")],
        ["Country", _fmt(geo.get("country"), UNKNOWN)],
        ["Region", _fmt(geo.get("region"), UNKNOWN)],
        ["City", _fmt(geo.get("city"), UNKNOWN)],
        ["ISP / Org", _fmt(geo.get("isp") or geo.get("org"), UNKNOWN)],
        ["Coordinates (lat, lon)", coords],
    ]
    elements.append(grid_table(geo_table_data, [4 * cm, 11 * cm]))
    elements.append(Spacer(1, 12))

    # --- Evidence / reasons ---
    elements.append(Paragraph("Evidence Summary", heading_style))
    reasons = verdict_data.get("reasons", [])
    if reasons:
        for reason in reasons:
            elements.append(Paragraph(f"\u2022 {reason}", normal))
    else:
        elements.append(Paragraph("No specific evidence flags were triggered.", normal))
    elements.append(Spacer(1, 12))

    # --- Links & threat intel ---
    links = parsed.get("links") or []
    threat_intel = case_meta.get("threat_intel") or {}
    ti_details = {d.get("url"): d for d in threat_intel.get("details", [])} if threat_intel else {}
    if links:
        elements.append(Paragraph("Links Found in Body & Threat-Intel Results", heading_style))
        link_rows = [["URL", "VirusTotal", "PhishTank", "Flagged?"]]
        for link in links[:10]:
            detail = ti_details.get(link, {})
            vt = detail.get("virustotal", {})
            pt = detail.get("phishtank", {})
            vt_status = vt.get("status", "unchecked")
            pt_status = pt.get("status", "unchecked")
            flagged = "YES" if detail.get("malicious") else ("No" if detail else "Not checked")
            link_rows.append([Paragraph(link, mono_small), vt_status, pt_status, flagged])
        elements.append(grid_table(link_rows, [6.3 * cm, 2.9 * cm, 2.9 * cm, 2.9 * cm], header_row=True))
        if not threat_intel.get("vt_key_configured", True):
            elements.append(Paragraph(
                "Note: no VirusTotal API key was configured at analysis time, so VirusTotal results "
                "above show as 'no_api_key' rather than a real verdict.", small_grey))
        elements.append(Spacer(1, 12))

    # --- Attachments ---
    attachments = parsed.get("attachments") or []
    if attachments:
        elements.append(Paragraph("Attachments", heading_style))
        att_rows = [["Filename"]] + [[a] for a in attachments]
        elements.append(grid_table(att_rows, [15.5 * cm], header_row=True))
        elements.append(Spacer(1, 12))

    # --- Analyst review / override ---
    if case_meta.get("reviewed") or case_meta.get("analyst_notes") or case_meta.get("analyst_override_verdict"):
        elements.append(Paragraph("Analyst Review / Override", heading_style))
        review_rows = [
            ["Reviewed by analyst", "Yes" if case_meta.get("reviewed") else "No"],
            ["Override verdict", _fmt(case_meta.get("analyst_override_verdict"), "(no override — engine verdict stands)")],
            ["Reviewed at", _fmt_dt(case_meta.get("analyst_reviewed_at")) if case_meta.get("analyst_reviewed_at") else UNKNOWN],
            ["Analyst notes", p(case_meta.get("analyst_notes") or "(none entered)")],
        ]
        elements.append(grid_table(review_rows, [4 * cm, 11.5 * cm]))
        elements.append(Spacer(1, 12))

    # --- Received header chain (chain of custody) ---
    received_chain = parsed.get("received_chain") or []
    if received_chain:
        elements.append(Paragraph("Received Header Chain (Chain of Custody)", heading_style))
        elements.append(Paragraph(
            "Listed in the order they appear in the message, top (last hop / most recent) to bottom "
            "(first hop / oldest). The originating IP above was derived by scanning this chain from "
            "the bottom up for the first public IP address.", small_grey))
        elements.append(Spacer(1, 4))
        for i, hop in enumerate(received_chain, 1):
            elements.append(Paragraph(f"Hop {i}:", ParagraphStyle("HopLabel", parent=normal, fontSize=8, textColor=colors.grey, spaceBefore=4)))
            elements.append(Paragraph(hop, mono_small))
        elements.append(Spacer(1, 12))

    elements.append(HRFlowable(width="100%", color=colors.grey))
    elements.append(Paragraph(
        "This report was auto-generated by SentinelMail AI for triage and "
        "investigative purposes. It should be corroborated by a human analyst "
        "before action is taken.", ParagraphStyle("Footer", parent=normal, fontSize=8, textColor=colors.grey, spaceBefore=6)
    ))

    doc.build(elements)
    return output_path
