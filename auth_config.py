import os

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "vpawankumar2025@gmail.com").strip().lower()

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

OTP_EXPIRE_MINUTES = 5
OTP_LENGTH = 6

# SMTP (email OTP)
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")

# SMS (Twilio)
# TWILIO_SID is always your Account SID (starts with AC) — Twilio needs to know
# which account to bill/send from either way.
# For authentication, either set TWILIO_AUTH_TOKEN (the account's master secret),
# OR set TWILIO_API_KEY_SID + TWILIO_API_KEY_SECRET (an API Key, starts with SK) —
# the latter is Twilio's own recommended approach since a leaked API key can be
# revoked individually without invalidating the whole account's Auth Token.
TWILIO_SID = os.environ.get("TWILIO_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_API_KEY_SID = os.environ.get("TWILIO_API_KEY_SID", "")
TWILIO_API_KEY_SECRET = os.environ.get("TWILIO_API_KEY_SECRET", "")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER", "")

# Google OAuth
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")

# --- Direct mailbox connection (OAuth, read-only inbox access) ---
# These are deliberately separate from GOOGLE_CLIENT_ID above: that one is only
# used to verify a one-shot Google Sign-In id_token, while this one needs a
# "Web application" OAuth client with a real redirect URI and a client secret,
# because reading someone's inbox on an ongoing basis requires offline access
# (a refresh token), which the Sign-In flow above never requests.
GMAIL_OAUTH_CLIENT_ID = os.environ.get("GMAIL_OAUTH_CLIENT_ID", "")
GMAIL_OAUTH_CLIENT_SECRET = os.environ.get("GMAIL_OAUTH_CLIENT_SECRET", "")
GMAIL_OAUTH_REDIRECT_URI = os.environ.get("GMAIL_OAUTH_REDIRECT_URI", "http://localhost:8000/api/mailbox/callback/google")

MS_OAUTH_CLIENT_ID = os.environ.get("MS_OAUTH_CLIENT_ID", "")
MS_OAUTH_CLIENT_SECRET = os.environ.get("MS_OAUTH_CLIENT_SECRET", "")
MS_OAUTH_TENANT = os.environ.get("MS_OAUTH_TENANT", "common")  # "common" = personal + work/school accounts
MS_OAUTH_REDIRECT_URI = os.environ.get("MS_OAUTH_REDIRECT_URI", "http://localhost:8000/api/mailbox/callback/microsoft")

MAILBOX_POLL_INTERVAL_MINUTES = int(os.environ.get("MAILBOX_POLL_INTERVAL_MINUTES", 3))
MAILBOX_INGEST_USER_TAG = "mailbox-sync"  # filename tag so synced cases are distinguishable from manual uploads


def determine_role(email: str) -> str:
    """Single source of truth for who is admin — always by email match, never by signup order.
    Called on every user-creation path (password signup, first Google login), so the admin
    seat is never an accident of who happened to register first."""
    return "admin" if email.strip().lower() == ADMIN_EMAIL else "user"
