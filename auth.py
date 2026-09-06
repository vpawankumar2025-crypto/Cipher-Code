import random
import string
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage

from jose import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Header
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

import db
from auth_config import (
    SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
    OTP_EXPIRE_MINUTES, OTP_LENGTH,
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS,
    TWILIO_SID, TWILIO_AUTH_TOKEN, TWILIO_API_KEY_SID, TWILIO_API_KEY_SECRET, TWILIO_FROM_NUMBER,
    GOOGLE_CLIENT_ID,
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload  # {"sub": user_id, "email": ..., "role": ...}


def require_admin(current_user=Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ---------- OAuth state (mailbox connect flow) ----------
# Google/Microsoft redirect the browser straight back to our callback with no
# Authorization header attached — it's a plain navigation, not a fetch() call.
# So identity has to travel inside the OAuth `state` param instead. Reusing the
# same JWT signing as login tokens keeps this tamper-proof without a new secret,
# just with a much shorter expiry since it only needs to survive one consent screen.

def create_oauth_state(user_id: int, provider: str) -> str:
    payload = {
        "user_id": user_id,
        "provider": provider,
        "purpose": "mailbox_oauth_state",
        "exp": datetime.utcnow() + timedelta(minutes=10),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_oauth_state(state: str) -> dict:
    payload = jwt.decode(state, SECRET_KEY, algorithms=[ALGORITHM])
    if payload.get("purpose") != "mailbox_oauth_state":
        raise ValueError("Not a mailbox OAuth state token")
    return payload


# ---------- OTP ----------

def _generate_code() -> str:
    return "".join(random.choices(string.digits, k=OTP_LENGTH))


def issue_otp(identifier: str, channel: str, purpose: str) -> str:
    """channel is 'email' or 'sms'. Generates a code, stores its hash, and dispatches it."""
    code = _generate_code()
    session = db.get_session()
    try:
        otp = db.OTP(
            identifier=identifier,
            channel=channel,
            purpose=purpose,
            code_hash=hash_password(code),
            expires_at=datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES),
        )
        session.add(otp)
        session.commit()
    finally:
        session.close()

    if channel == "email":
        send_email_otp(identifier, code)
    elif channel == "sms":
        send_sms_otp(identifier, code)
    else:
        raise ValueError(f"Unknown OTP channel: {channel}")
    return code  # don't return this in API responses in production — kept for local testing only


def verify_otp(identifier: str, code: str, purpose: str, channel: str) -> bool:
    session = db.get_session()
    try:
        otp = (
            session.query(db.OTP)
            .filter(
                db.OTP.identifier == identifier,
                db.OTP.purpose == purpose,
                db.OTP.channel == channel,
                db.OTP.consumed == False,  # noqa: E712
            )
            .order_by(db.OTP.created_at.desc())
            .first()
        )
        if not otp or otp.expires_at < datetime.utcnow():
            return False
        if not verify_password(code, otp.code_hash):
            return False
        otp.consumed = True
        session.commit()
        return True
    finally:
        session.close()


def send_email_otp(to_email: str, code: str):
    msg = EmailMessage()
    msg["Subject"] = "Your SentinelMail verification code"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(f"Your OTP is {code}. It expires in {OTP_EXPIRE_MINUTES} minutes.")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def send_sms_otp(to_mobile: str, code: str):
    from twilio.rest import Client
    # Prefer an API Key (SK... + secret) when set — Twilio's recommended approach,
    # since it can be revoked on its own without touching the main Auth Token.
    # Either way, the account being sent from is always TWILIO_SID (the AC... Account SID).
    if TWILIO_API_KEY_SID and TWILIO_API_KEY_SECRET:
        client = Client(TWILIO_API_KEY_SID, TWILIO_API_KEY_SECRET, TWILIO_SID)
    else:
        client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
    client.messages.create(
        body=f"Your SentinelMail OTP is {code}. Expires in {OTP_EXPIRE_MINUTES} min.",
        from_=TWILIO_FROM_NUMBER,
        to=to_mobile,
    )


# ---------- Google OAuth ----------

def verify_google_id_token(token: str) -> dict:
    """Returns {'email':..., 'sub':..., 'name':...} or raises."""
    idinfo = google_id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
    return idinfo
