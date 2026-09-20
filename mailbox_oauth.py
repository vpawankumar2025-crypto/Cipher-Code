"""
mailbox_oauth.py
OAuth (not password-based) connection to a user's real Gmail or Outlook inbox,
so SentinelMail can pull and score new mail automatically — no manual .eml
export needed.

Two providers, both read-only:
  - Google:    scope "gmail.readonly", via Google's OAuth 2.0 + Gmail REST API
  - Microsoft: scope "Mail.Read",      via Microsoft identity platform + Graph API

Both APIs are called with plain `requests` rather than their official SDKs, to
avoid pulling in heavy client libraries for what's fundamentally four HTTP
endpoints per provider (authorize, token, profile, list/get messages).

Setup required before this works (see README for the full walkthrough):
  Google:    a "Web application" OAuth client in Google Cloud Console, with
             GMAIL_OAUTH_REDIRECT_URI added as an authorized redirect URI.
  Microsoft: an "App registration" in Azure Portal (Entra ID), with
             MS_OAUTH_REDIRECT_URI added as a redirect URI, and a client secret.
"""

import base64
import email as email_module
from datetime import datetime, timedelta

import requests

from auth_config import (
    GMAIL_OAUTH_CLIENT_ID, GMAIL_OAUTH_CLIENT_SECRET, GMAIL_OAUTH_REDIRECT_URI,
    MS_OAUTH_CLIENT_ID, MS_OAUTH_CLIENT_SECRET, MS_OAUTH_TENANT, MS_OAUTH_REDIRECT_URI,
)

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPE = "https://www.googleapis.com/auth/gmail.readonly email profile openid"

MS_SCOPE = "offline_access Mail.Read User.Read"


class MailboxOAuthError(Exception):
    pass


def _ms_authority():
    return f"https://login.microsoftonline.com/{MS_OAUTH_TENANT}"


# ---------------- Step 1: build the consent-screen URL ----------------

def build_auth_url(provider: str, state: str) -> str:
    if provider == "google":
        if not (GMAIL_OAUTH_CLIENT_ID and GMAIL_OAUTH_CLIENT_SECRET):
            raise MailboxOAuthError(
                "GMAIL_OAUTH_CLIENT_ID / GMAIL_OAUTH_CLIENT_SECRET not set — "
                "create a Google Cloud OAuth client first (see README)."
            )
        params = {
            "client_id": GMAIL_OAUTH_CLIENT_ID,
            "redirect_uri": GMAIL_OAUTH_REDIRECT_URI,
            "response_type": "code",
            "scope": GOOGLE_SCOPE,
            "access_type": "offline",   # required to get a refresh_token
            "prompt": "consent",        # forces refresh_token on every connect, not just the first
            "state": state,
        }
        return GOOGLE_AUTH_ENDPOINT + "?" + requests.compat.urlencode(params)

    if provider == "microsoft":
        if not (MS_OAUTH_CLIENT_ID and MS_OAUTH_CLIENT_SECRET):
            raise MailboxOAuthError(
                "MS_OAUTH_CLIENT_ID / MS_OAUTH_CLIENT_SECRET not set — "
                "register an app in Azure Portal first (see README)."
            )
        params = {
            "client_id": MS_OAUTH_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": MS_OAUTH_REDIRECT_URI,
            "response_mode": "query",
            "scope": MS_SCOPE,
            "state": state,
        }
        return f"{_ms_authority()}/oauth2/v2.0/authorize?" + requests.compat.urlencode(params)

    raise MailboxOAuthError(f"Unknown provider: {provider}")


# ---------------- Step 2: exchange the code for tokens ----------------

def exchange_code(provider: str, code: str) -> dict:
    """Returns {access_token, refresh_token, expires_at (datetime), email_address}."""
    if provider == "google":
        resp = requests.post(GOOGLE_TOKEN_ENDPOINT, data={
            "client_id": GMAIL_OAUTH_CLIENT_ID,
            "client_secret": GMAIL_OAUTH_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GMAIL_OAUTH_REDIRECT_URI,
        }, timeout=15)
        if not resp.ok:
            raise MailboxOAuthError(f"Google token exchange failed: {resp.text[:300]}")
        data = resp.json()
        if "refresh_token" not in data:
            raise MailboxOAuthError(
                "Google didn't return a refresh_token — this happens if the account already "
                "granted consent before without 'prompt=consent'. Revoke access at "
                "myaccount.google.com/permissions and try connecting again."
            )
        email_address = _google_profile_email(data["access_token"])
        return {
            "access_token": data["access_token"],
            "refresh_token": data["refresh_token"],
            "expires_at": datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600)),
            "email_address": email_address,
        }

    if provider == "microsoft":
        resp = requests.post(f"{_ms_authority()}/oauth2/v2.0/token", data={
            "client_id": MS_OAUTH_CLIENT_ID,
            "client_secret": MS_OAUTH_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": MS_OAUTH_REDIRECT_URI,
            "scope": MS_SCOPE,
        }, timeout=15)
        if not resp.ok:
            raise MailboxOAuthError(f"Microsoft token exchange failed: {resp.text[:300]}")
        data = resp.json()
        email_address = _ms_profile_email(data["access_token"])
        return {
            "access_token": data["access_token"],
            "refresh_token": data["refresh_token"],
            "expires_at": datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600)),
            "email_address": email_address,
        }

    raise MailboxOAuthError(f"Unknown provider: {provider}")


def _google_profile_email(access_token: str) -> str:
    resp = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["emailAddress"]


def _ms_profile_email(access_token: str) -> str:
    resp = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("mail") or data.get("userPrincipalName")


# ---------------- Step 3: refresh an expired access token ----------------

def refresh_access_token(provider: str, refresh_token: str) -> dict:
    """Returns {access_token, expires_at}."""
    if provider == "google":
        resp = requests.post(GOOGLE_TOKEN_ENDPOINT, data={
            "client_id": GMAIL_OAUTH_CLIENT_ID,
            "client_secret": GMAIL_OAUTH_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }, timeout=15)
    elif provider == "microsoft":
        resp = requests.post(f"{_ms_authority()}/oauth2/v2.0/token", data={
            "client_id": MS_OAUTH_CLIENT_ID,
            "client_secret": MS_OAUTH_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": MS_SCOPE,
        }, timeout=15)
    else:
        raise MailboxOAuthError(f"Unknown provider: {provider}")

    if not resp.ok:
        raise MailboxOAuthError(f"{provider} token refresh failed: {resp.text[:300]}")
    data = resp.json()
    return {
        "access_token": data["access_token"],
        "expires_at": datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600)),
    }


# ---------------- Step 4: list new messages + fetch raw MIME ----------------
# Both use timestamp-based polling (messages since last_synced_at) rather than
# each provider's incremental-sync token (Gmail historyId / Graph delta link).
# That's a deliberate simplification: history/delta tokens can expire and need
# resync-from-scratch handling, which is real production hardening a hackathon
# build doesn't need. Timestamp polling is simpler, idempotent, and good enough
# at a multi-minute poll interval.

def list_new_message_ids(provider: str, access_token: str, since: datetime) -> list:
    since = since or (datetime.utcnow() - timedelta(days=1))  # first sync: last 24h only

    if provider == "google":
        epoch_seconds = int(since.timestamp())
        resp = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"q": f"after:{epoch_seconds}", "maxResults": 25},
            timeout=15,
        )
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("messages", [])]

    if provider == "microsoft":
        iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.get(
            "https://graph.microsoft.com/v1.0/me/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={
                "$filter": f"receivedDateTime ge {iso}",
                "$select": "id",
                "$top": 25,
                "$orderby": "receivedDateTime asc",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return [m["id"] for m in resp.json().get("value", [])]

    raise MailboxOAuthError(f"Unknown provider: {provider}")


def fetch_raw_message(provider: str, access_token: str, message_id: str) -> bytes:
    """Returns the full raw RFC822 bytes — i.e. exactly what a .eml file contains,
    so it can go straight into the existing eml_parser.parse_eml() unchanged."""
    if provider == "google":
        resp = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"format": "raw"},
            timeout=20,
        )
        resp.raise_for_status()
        raw_b64url = resp.json()["raw"]
        return base64.urlsafe_b64decode(raw_b64url + "==")  # padding tolerant

    if provider == "microsoft":
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0/me/messages/{message_id}/$value",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.content

    raise MailboxOAuthError(f"Unknown provider: {provider}")
