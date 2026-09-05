"""
app.py
SentinelMail AI — Streamlit demo UI
Run with: streamlit run app.py
"""

import streamlit as st
import tempfile
import os


from eml_parser import parse_eml
from geoip_lookup import geolocate_ip
from scoring import score_email
from report_generator import generate_report

st.set_page_config(page_title="SentinelMail AI", page_icon="🛡️", layout="wide")

st.title("🛡️ SentinelMail AI")
st.caption("AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform")

st.markdown("---")

uploaded_file = st.file_uploader("Upload an email (.eml file)", type=["eml"])

col_a, col_b = st.columns(2)
with col_a:
    st.info("Don't have a sample? Try the bundled test emails:")
    sample_choice = st.selectbox(
        "Or pick a sample email",
        ["(none)", "samples/clean_email.eml", "samples/phishing_email.eml"],
    )

if uploaded_file is not None or sample_choice != "(none)":
    if uploaded_file is not None:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".eml")
        tmp.write(uploaded_file.read())
        tmp.close()
        eml_path = tmp.name
        source_name = uploaded_file.name
    else:
        eml_path = sample_choice
        source_name = sample_choice.split("/")[-1]

    with st.spinner("Analyzing email..."):
        parsed = parse_eml(eml_path)
        geo = geolocate_ip(parsed.get("originating_ip"))
        verdict_data = score_email(parsed, geo)

    st.markdown("## Analysis Result")

    verdict = verdict_data["verdict"]
    score = verdict_data["score"]

    verdict_colors = {"Safe": "green", "Suspicious": "orange", "Malicious": "red"}
    st.markdown(
        f"### Verdict: :{verdict_colors.get(verdict,'gray')}[{verdict}]  "
        f"&nbsp;&nbsp; Risk Score: **{score}/100**"
    )
    st.progress(score / 100)

    col1, col2, col3 = st.columns(3)
    col1.metric("SPF", parsed.get("spf_result", "none").upper())
    col2.metric("DKIM", parsed.get("dkim_result", "none").upper())
    col3.metric("DMARC", parsed.get("dmarc_result", "none").upper())

    st.markdown("### 📧 Email Metadata")
    st.write({
        "From": parsed.get("from"),
        "Reply-To": parsed.get("reply_to") or "(none)",
        "Subject": parsed.get("subject"),
        "Date": parsed.get("date"),
    })

    st.markdown("### 🌍 Sender IP & Geolocation")
    if parsed.get("originating_ip"):
        gcol1, gcol2 = st.columns(2)
        gcol1.write(f"**IP Address:** {parsed['originating_ip']}")
        if geo.get("status") == "success":
            gcol2.write(f"**Location:** {geo['city']}, {geo['region']}, {geo['country']}")
            st.write(f"**ISP/Org:** {geo.get('isp', 'Unknown')}")
            if geo.get("lat") and geo.get("lon"):
                import pandas as pd
                st.map(pd.DataFrame({"lat": [geo["lat"]], "lon": [geo["lon"]]}))
        else:
            st.warning(f"Geolocation lookup unavailable ({geo.get('status')}). Check internet connection.")
    else:
        st.warning("Could not determine originating IP from email headers.")

    st.markdown("### 🔍 Evidence Summary")
    if verdict_data["reasons"]:
        for reason in verdict_data["reasons"]:
            st.write(f"- {reason}")
    else:
        st.write("No suspicious indicators detected.")

    if parsed.get("links"):
        st.markdown("### 🔗 Links Found")
        for link in parsed["links"]:
            st.code(link)

    if parsed.get("attachments"):
        st.markdown("### 📎 Attachments")
        st.write(parsed["attachments"])

    st.markdown("---")
    if st.button("📄 Generate Forensic PDF Report"):
        out_path = os.path.join(tempfile.gettempdir(), f"{source_name}_report.pdf")
        generate_report(parsed, geo, verdict_data, out_path)
        with open(out_path, "rb") as f:
            st.download_button(
                "⬇️ Download Forensic Report",
                data=f.read(),
                file_name=f"SentinelMail_Report_{source_name}.pdf",
                mime="application/pdf",
            )
        st.success("Forensic report generated successfully.")

else:
    st.write("👆 Upload an `.eml` file or select a sample to begin analysis.")

st.markdown("---")
st.caption("SentinelMail AI — SIH26106 Prototype | Rule-based scoring engine (MVP) — swappable with trained ML model")
