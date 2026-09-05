"""
report_generator.py
Generates a forensic-grade PDF report summarizing the email analysis:
verdict, evidence, authentication results, and geolocation.
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


def generate_report(parsed: dict, geo: dict, verdict_data: dict, output_path: str):
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], fontSize=20)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], spaceBefore=14)
    normal = styles["Normal"]

    verdict_color = VERDICT_COLORS.get(verdict_data["verdict"], colors.black)
    verdict_style = ParagraphStyle(
        "Verdict", parent=styles["Heading1"], textColor=verdict_color, fontSize=22
    )

    elements = []

    elements.append(Paragraph("SentinelMail AI — Forensic Analysis Report", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
    elements.append(HRFlowable(width="100%", color=colors.grey, spaceBefore=10, spaceAfter=10))

    # --- Verdict block ---
    elements.append(Paragraph(f"Verdict: {verdict_data['verdict']}", verdict_style))
    elements.append(Paragraph(f"Risk Score: {verdict_data['score']} / 100", normal))
    elements.append(Spacer(1, 12))

    # --- Email metadata table ---
    elements.append(Paragraph("Email Metadata", heading_style))
    meta_table_data = [
        ["From", parsed.get("from", "")],
        ["Reply-To", parsed.get("reply_to", "") or "(none)"],
        ["To", parsed.get("to", "")],
        ["Subject", parsed.get("subject", "")],
        ["Date", parsed.get("date", "")],
        ["Message-ID", parsed.get("message_id", "") or "(none)"],
    ]
    meta_table = Table(meta_table_data, colWidths=[3.5 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # --- Authentication results ---
    elements.append(Paragraph("Email Authentication Results", heading_style))
    auth_table_data = [
        ["Mechanism", "Result"],
        ["SPF", parsed.get("spf_result", "none")],
        ["DKIM", parsed.get("dkim_result", "none")],
        ["DMARC", parsed.get("dmarc_result", "none")],
    ]
    auth_table = Table(auth_table_data, colWidths=[6 * cm, 6 * cm])
    auth_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(auth_table)
    elements.append(Spacer(1, 12))

    # --- Geolocation ---
    elements.append(Paragraph("Sender IP & Geolocation", heading_style))
    geo_table_data = [
        ["Originating IP", parsed.get("originating_ip") or "Not determined"],
        ["Country", geo.get("country", "Unknown")],
        ["Region", geo.get("region", "Unknown")],
        ["City", geo.get("city", "Unknown")],
        ["ISP / Org", geo.get("isp", "Unknown")],
    ]
    geo_table = Table(geo_table_data, colWidths=[4 * cm, 11 * cm])
    geo_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(geo_table)
    elements.append(Spacer(1, 12))

    # --- Evidence / reasons ---
    elements.append(Paragraph("Evidence Summary", heading_style))
    for reason in verdict_data.get("reasons", []):
        elements.append(Paragraph(f"• {reason}", normal))
    elements.append(Spacer(1, 12))

    # --- Links & attachments ---
    if parsed.get("links"):
        elements.append(Paragraph("Links Found in Body", heading_style))
        for link in parsed["links"][:10]:
            elements.append(Paragraph(link, normal))

    if parsed.get("attachments"):
        elements.append(Paragraph("Attachments", heading_style))
        for att in parsed["attachments"]:
            elements.append(Paragraph(att, normal))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", color=colors.grey))
    elements.append(Paragraph(
        "This report was auto-generated by SentinelMail AI for triage and "
        "investigative purposes. It should be corroborated by a human analyst "
        "before action is taken.", ParagraphStyle("Footer", parent=normal, fontSize=8, textColor=colors.grey)
    ))

    doc.build(elements)
    return output_path
