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
import json
import html
import tempfile
from dotenv import load_dotenv
load_dotenv()  # must run before importing auth/db, since auth_config reads os.environ at import time

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from eml_parser import parse_eml
from geoip_lookup import geolocate_ip
from threat_intel import check_links
from scoring import score_email
from report_generator import generate_report
from pydantic import EmailStr
import db
import auth
import mailbox_oauth
import mailbox_poller

app = FastAPI(title="SentinelMail AI API")

# Poll every connected Gmail/Outlook mailbox on a background schedule — this is
# what makes direct-connect inboxes show up automatically. Guarded so a
# `--reload` restart doesn't spin up a second overlapping scheduler.
_mailbox_scheduler = None


@app.on_event("startup")
def _start_mailbox_scheduler():
    global _mailbox_scheduler
    if _mailbox_scheduler is None:
        _mailbox_scheduler = mailbox_poller.start_scheduler()

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


class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    mobile: str
    password: str


class LoginRequest(BaseModel):
    identifier: str   # username, email, or mobile
    password: str


class OTPRequest(BaseModel):
    identifier: str
    channel: str        # "email" or "sms"
    purpose: str         # "signup" or "login"


class OTPVerify(BaseModel):
    identifier: str
    code: str
    purpose: str
    channel: str


class GoogleLoginRequest(BaseModel):
    id_token: str


@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...), current_user=Depends(auth.get_current_user)):
    contents = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        parsed = parse_eml(tmp_path)
        geo = geolocate_ip(parsed.get("originating_ip"))
        threat_intel_result = check_links(parsed.get("links", []))
        verdict_data = score_email(parsed, geo, threat_intel_result)
        case_id = db.save_case(parsed, geo, verdict_data, threat_intel_result,
                                filename=file.filename, user_id=int(current_user["sub"]))
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
def list_all_cases(limit: int = 100, current_user=Depends(auth.get_current_user)):
    """Regular users see only their own cases. Admins see everyone's here too —
    use /api/admin/cases if you specifically want the all-users admin view."""
    is_admin = current_user.get("role") == "admin"
    return db.list_cases(user_id=int(current_user["sub"]), is_admin=is_admin, limit=limit)


@app.get("/api/cases/{case_id}")
def get_case_detail(case_id: int, current_user=Depends(auth.get_current_user)):
    is_admin = current_user.get("role") == "admin"
    case = db.get_case(case_id, user_id=int(current_user["sub"]), is_admin=is_admin)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/api/cases/{case_id}/override")
def override_case_verdict(case_id: int, body: OverrideRequest, current_user=Depends(auth.get_current_user)):
    is_admin = current_user.get("role") == "admin"
    success = db.override_verdict(case_id, body.verdict, user_id=int(current_user["sub"]),
                                   is_admin=is_admin, notes=body.notes)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True, "case_id": case_id, "new_verdict": body.verdict}


@app.get("/api/cases/{case_id}/report")
def download_case_report(case_id: int, current_user=Depends(auth.get_current_user)):
    is_admin = current_user.get("role") == "admin"
    case = db.get_case(case_id, user_id=int(current_user["sub"]), is_admin=is_admin)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Prefer the full parser/geo payload captured at analysis time (present for
    # every case analyzed after parsed_json/geo_json were added). Fall back to
    # the flat columns for older cases saved before that, so reports for those
    # still generate instead of erroring — just with fewer fields available.
    stored_parsed = case.get("parsed") or {}
    stored_geo = case.get("geo_full") or {}

    parsed = {
        "from": stored_parsed.get("from") or case["sender"],
        "reply_to": stored_parsed.get("reply_to", ""),
        "to": stored_parsed.get("to", ""),
        "subject": stored_parsed.get("subject") or case["subject"],
        "date": stored_parsed.get("date") or case["received_date"],
        "message_id": stored_parsed.get("message_id", ""),
        "originating_ip": stored_parsed.get("originating_ip") or case["originating_ip"],
        "spf_result": stored_parsed.get("spf_result") or case["spf_result"],
        "dkim_result": stored_parsed.get("dkim_result") or case["dkim_result"],
        "dmarc_result": stored_parsed.get("dmarc_result") or case["dmarc_result"],
        "auth_results_raw": stored_parsed.get("auth_results_raw", ""),
        "links": stored_parsed.get("links") or [d["url"] for d in case["threat_intel"].get("details", [])],
        "attachments": stored_parsed.get("attachments", []),
        "received_chain": stored_parsed.get("received_chain", []),
        "display_name": stored_parsed.get("display_name", ""),
        "from_address": stored_parsed.get("from_address", ""),
    }
    geo = {
        "country": stored_geo.get("country") or case["geo_country"],
        "region": stored_geo.get("region", ""),
        "city": stored_geo.get("city") or case["geo_city"],
        "isp": stored_geo.get("isp") or case["geo_isp"],
        "org": stored_geo.get("org", ""),
        "lat": stored_geo.get("lat"),
        "lon": stored_geo.get("lon"),
    }
    verdict_data = {
        "score": case["final_score"],
        "rule_score": case["rule_based_score"],
        "ml_probability": case["ml_phishing_probability"],
        "verdict": case["analyst_override_verdict"] or case["verdict"],
        "engine_verdict": case["verdict"],
        "reasons": case["reasons"],
    }
    case_meta = {
        "case_id": case["id"],
        "filename": case["filename"],
        "analyzed_at": case["created_at"],
        "reviewed": case["reviewed"],
        "analyst_override_verdict": case["analyst_override_verdict"],
        "analyst_notes": case["analyst_notes"],
        "analyst_reviewed_at": case["analyst_reviewed_at"],
        "threat_intel": case["threat_intel"],
    }

    out_path = os.path.join(tempfile.gettempdir(), f"case_{case_id}_report.pdf")
    generate_report(parsed, geo, verdict_data, out_path, case_meta=case_meta)
    return FileResponse(out_path, media_type="application/pdf",
                         filename=f"SentinelMail_Case_{case_id}_Report.pdf")


@app.get("/api/dashboard/stats")
def get_dashboard_stats(current_user=Depends(auth.get_current_user)):
    is_admin = current_user.get("role") == "admin"
    return db.dashboard_stats(user_id=int(current_user["sub"]), is_admin=is_admin)


# ---------------------- Admin-only ----------------------

@app.get("/api/admin/cases")
def admin_list_all_cases(limit: int = 100, current_user=Depends(auth.require_admin)):
    """Every user's cases, regardless of owner — admin only."""
    return db.list_cases(user_id=int(current_user["sub"]), is_admin=True, limit=limit)


@app.get("/")
def root():
    return {"status": "SentinelMail AI backend running", "docs": "/docs"}


# ---------------------- Auth ----------------------

@app.post("/api/auth/check")
def check_identifier(identifier: str):
    """Frontend calls this first to decide: show the signup form or the login form."""
    return {"exists": db.get_user_by_identifier(identifier) is not None}


@app.post("/api/auth/signup")
def signup(body: SignupRequest):
    if (db.get_user_by_identifier(body.username)
            or db.get_user_by_identifier(body.email)
            or db.get_user_by_identifier(body.mobile)):
        raise HTTPException(status_code=409, detail="Username, email, or mobile already registered")

    user = db.create_user(
        username=body.username,
        email=body.email,
        mobile=body.mobile,
        password_hash=auth.hash_password(body.password),
    )
    # Dual verification: an OTP goes to both channels; the account is only fully
    # verified once both have been confirmed (see db.mark_channel_verified).
    auth.issue_otp(user.email, channel="email", purpose="signup")
    auth.issue_otp(user.mobile, channel="sms", purpose="signup")
    return {
        "message": "Signup successful. Enter the OTP codes sent to your email and mobile to verify your account.",
        "user_id": user.id,
        "requires_verification": ["email", "sms"],
    }


@app.post("/api/auth/otp/request")
def request_otp(body: OTPRequest):
    user = db.get_user_by_identifier(body.identifier)
    if not user and body.purpose == "login":
        raise HTTPException(status_code=404, detail="No account found")
    auth.issue_otp(body.identifier, body.channel, body.purpose)
    return {"message": f"OTP sent via {body.channel}"}


@app.post("/api/auth/otp/verify")
def verify_otp_endpoint(body: OTPVerify):
    if not auth.verify_otp(body.identifier, body.code, body.purpose, body.channel):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user = db.get_user_by_identifier(body.identifier)
    if body.purpose == "signup":
        db.mark_channel_verified(user.id, body.channel)
        user = db.get_user_by_identifier(body.identifier)  # re-fetch to see updated is_verified

    if not user.is_verified and body.purpose == "signup":
        return {"message": f"{body.channel} verified. Still waiting on the other channel.", "fully_verified": False}

    token = auth.create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "role": user.role, "fully_verified": True}


@app.post("/api/auth/login")
def login(body: LoginRequest):
    user = db.get_user_by_identifier(body.identifier)
    if not user or not user.password_hash or not auth.verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Account not verified — complete OTP verification for both email and mobile first")
    token = auth.create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@app.post("/api/auth/google")
def google_login(body: GoogleLoginRequest):
    idinfo = auth.verify_google_id_token(body.id_token)
    email = idinfo["email"]
    user = db.get_user_by_identifier(email)
    if not user:
        user = db.create_user(
            username=email.split("@")[0],
            email=email,
            mobile=None,
            google_id=idinfo["sub"],
        )
        db.set_fully_verified(user.id)  # Google already verified the email; no mobile to check
        user = db.get_user_by_identifier(email)
    token = auth.create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@app.get("/api/auth/me")
def get_me(current_user=Depends(auth.get_current_user)):
    return current_user


# ---------------------- Direct mailbox connection (OAuth) ----------------------

@app.post("/api/mailbox/connect/{provider}")
def mailbox_connect(provider: str, current_user=Depends(auth.get_current_user)):
    """Returns a Google/Microsoft consent-screen URL for the frontend to open
    in a popup. `state` is a short-lived signed token carrying the user's id,
    so the callback below — which arrives as a plain browser redirect with no
    Authorization header — still knows which account to attach the mailbox to."""
    if provider not in ("google", "microsoft"):
        raise HTTPException(status_code=400, detail="provider must be 'google' or 'microsoft'")

    state = auth.create_oauth_state(user_id=int(current_user["sub"]), provider=provider)
    try:
        auth_url = mailbox_oauth.build_auth_url(provider, state)
    except mailbox_oauth.MailboxOAuthError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"auth_url": auth_url}


@app.get("/api/mailbox/callback/{provider}", response_class=HTMLResponse)
def mailbox_callback(provider: str, code: str = None, state: str = None, error: str = None):
    """Google/Microsoft redirect the browser here after consent. This can't
    carry an Authorization header (it's a plain browser navigation, not a
    fetch() call from the dashboard), so identity comes from the signed
    `state` value instead. Returns a tiny HTML page that messages the opener
    window and closes itself, so the dashboard popup flow can pick up cleanly.

    SECURITY: `provider` (path) and `error` (query) are attacker-controlled —
    this endpoint has no auth, since it's the OAuth redirect target. Both are
    validated/escaped below before ever touching the HTML/JS response. Do not
    reintroduce raw f-string interpolation of either into `_result_page`."""

    # Reject unknown providers up front instead of reflecting an arbitrary
    # path segment into the page.
    if provider not in ("google", "microsoft"):
        provider = "unknown"

    def _result_page(ok: bool, message: str) -> str:
        # json.dumps() gives a properly-escaped JS string literal (unlike the
        # old manual f-string version, it can't be broken out of with quotes
        # or a `</script>` sequence). html.escape() does the same for the
        # HTML body. Never interpolate `message`/`provider` unescaped again.
        payload = json.dumps({
            "type": "sentinelmail-oauth",
            "status": "success" if ok else "error",
            "provider": provider,
            "message": message,
        })
        safe_message = html.escape(message)
        return f"""
        <html><body style="font-family:sans-serif;background:#0B0E13;color:#E7EAEE;
        display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
          <div style="text-align:center;">
            <p>{safe_message}</p>
            <p style="color:#8B95A3;font-size:13px;">You can close this window.</p>
          </div>
          <script>
            if (window.opener) {{ window.opener.postMessage({payload}, '*'); }}
            setTimeout(function() {{ window.close(); }}, 1200);
          </script>
        </body></html>
        """

    if error:
        return HTMLResponse(_result_page(False, f"Connection cancelled: {error}"))
    if not code or not state:
        return HTMLResponse(_result_page(False, "Missing code or state from provider."))

    try:
        state_data = auth.verify_oauth_state(state)
    except Exception:
        return HTMLResponse(_result_page(False, "This connection link expired or is invalid — try connecting again."))

    if state_data.get("provider") != provider:
        return HTMLResponse(_result_page(False, "Provider mismatch — try connecting again."))

    try:
        tokens = mailbox_oauth.exchange_code(provider, code)
        db.upsert_mailbox(
            user_id=state_data["user_id"],
            provider=provider,
            email_address=tokens["email_address"],
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_expires_at=tokens["expires_at"],
        )
    except mailbox_oauth.MailboxOAuthError as e:
        return HTMLResponse(_result_page(False, str(e)))

    return HTMLResponse(_result_page(True, f"Connected {tokens['email_address']}."))


@app.get("/api/mailbox/list")
def mailbox_list(current_user=Depends(auth.get_current_user)):
    return db.list_mailboxes_for_user(int(current_user["sub"]))


@app.delete("/api/mailbox/{mailbox_id}")
def mailbox_disconnect(mailbox_id: int, current_user=Depends(auth.get_current_user)):
    ok = db.delete_mailbox(mailbox_id, int(current_user["sub"]))
    if not ok:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    return {"message": "Disconnected"}


@app.post("/api/mailbox/{mailbox_id}/sync")
def mailbox_sync_now(mailbox_id: int, current_user=Depends(auth.get_current_user)):
    """Triggers an immediate sync instead of waiting for the next scheduled poll — mainly for demos."""
    mailbox = db.get_mailbox(mailbox_id, user_id=int(current_user["sub"]))
    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    result = mailbox_poller.sync_mailbox(mailbox)
    if result["error"]:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
