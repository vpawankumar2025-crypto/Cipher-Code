"""
backend.py
FastAPI backend — matches the pitch deck's stated stack ("Python (FastAPI) backend").

Endpoints:
  POST /api/analyze          - upload an .eml file, run full pipeline, store case
  GET  /api/cases            - list all cases (for dashboard table)
  GET  /api/cases/{id}       - get full case detail
  POST /api/cases/{id}/override - analyst overrides the verdict
  GET  /api/cases/{id}/report   - download forensic PDF for a case
  GET  /api/dashboard/stats  - summary counts for dashboard header

Run: uvicorn backend:app --reload --port 8000
"""

import os
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from eml_parser import parse_eml
from geoip_lookup import geolocate_ip
from threat_intel import check_links
from scoring import score_email
from report_generator import generate_report
import db

app = FastAPI(title="SentinelMail AI API")

# Allow the React dashboard (served separately) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class OverrideRequest(BaseModel):
    verdict: str
    notes: str = ""


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    contents = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        parsed = parse_eml(tmp_path)
        geo = geolocate_ip(parsed.get("originating_ip"))
        threat_intel_result = check_links(parsed.get("links", []))
        verdict_data = score_email(parsed, geo, threat_intel_result)
        case_id = db.save_case(parsed, geo, verdict_data, threat_intel_result, filename=file.filename)
    finally:
        os.unlink(tmp_path)

    return {
        "case_id": case_id,
        "parsed": {
            "from": parsed.get("from"),
            "subject": parsed.get("subject"),
            "date": parsed.get("date"),
            "originating_ip": parsed.get("originating_ip"),
            "spf_result": parsed.get("spf_result"),
            "dkim_result": parsed.get("dkim_result"),
            "dmarc_result": parsed.get("dmarc_result"),
            "links": parsed.get("links"),
            "attachments": parsed.get("attachments"),
        },
        "geo": geo,
        "threat_intel": threat_intel_result,
        "verdict": verdict_data,
    }


@app.get("/api/cases")
def list_all_cases(limit: int = 100):
    return db.list_cases(limit=limit)


@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: int):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/api/cases/{case_id}/override")
def override_case_verdict(case_id: int, body: OverrideRequest):
    success = db.override_verdict(case_id, body.verdict, body.notes)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True, "case_id": case_id, "new_verdict": body.verdict}


@app.get("/api/cases/{case_id}/report")
def download_case_report(case_id: int):
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    parsed = {
        "from": case["sender"],
        "reply_to": "",
        "to": "",
        "subject": case["subject"],
        "date": case["received_date"],
        "message_id": "",
        "originating_ip": case["originating_ip"],
        "spf_result": case["spf_result"],
        "dkim_result": case["dkim_result"],
        "dmarc_result": case["dmarc_result"],
        "links": [d["url"] for d in case["threat_intel"].get("details", [])],
        "attachments": [],
    }
    geo = {
        "country": case["geo_country"],
        "region": "",
        "city": case["geo_city"],
        "isp": case["geo_isp"],
    }
    verdict_data = {
        "score": case["final_score"],
        "verdict": case["analyst_override_verdict"] or case["verdict"],
        "reasons": case["reasons"],
    }

    out_path = os.path.join(tempfile.gettempdir(), f"case_{case_id}_report.pdf")
    generate_report(parsed, geo, verdict_data, out_path)
    return FileResponse(out_path, media_type="application/pdf",
                         filename=f"SentinelMail_Case_{case_id}_Report.pdf")


@app.get("/api/dashboard/stats")
def get_dashboard_stats():
    return db.dashboard_stats()


@app.get("/")
def root():
    return {"status": "SentinelMail AI backend running", "docs": "/docs"}
