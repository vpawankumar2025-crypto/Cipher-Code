"""
domain_intel.py
Domain-registration intelligence: WHOIS lookups for the sender's domain.

The SIH26106 brief explicitly asks for "domain intelligence analysis using
WHOIS data, DNS records, MX records, hosting fingerprints, and registrar
details." DNS/MX already exist elsewhere in the pipeline (checkdmarc in
requirements.txt, DNS resolution in eml_parser/advanced_security); this
module adds the WHOIS half: registrar, registrant country, and — most
usefully for phishing detection — domain age.

Domain age is the single strongest WHOIS signal for phishing: a domain
registered a few days ago impersonating a bank or courier service is a
textbook attack pattern. checkdmarc / geoip_lookup.py's docstring flagged
this as a "extend with domain WHOIS lookups" TODO — this module is that
extension.

WHOIS lookups go out over TCP port 43 to registrar WHOIS servers (not HTTP),
so — like every other network-dependent module in this project
(geoip_lookup.py, threat_intel.py) — this fails closed with a clear status
field rather than raising, so a slow/unreachable WHOIS server never crashes
the analysis pipeline or blocks the demo. `quiet=True` is passed to the
underlying whois() call because the library prints (not raises) a
"Error trying to connect to socket" line straight to stdout on every
unreachable/blocked registrar server — harmless, but noisy enough during a
mailbox sync of several real emails to look like something is broken when
it isn't. A 6s timeout keeps one slow/unresponsive registrar from stalling
a batch sync of multiple emails.
"""

import re
from datetime import datetime, timezone

import whois

RECENT_REGISTRATION_DAYS = 90  # domains younger than this get flagged as suspicious


def extract_registrable_domain(address: str) -> str:
    """Pulls the registrable domain out of an email address or bare domain
    string, e.g. 'alerts@secure-bank-verify.co.uk' -> 'secure-bank-verify.co.uk'.
    Deliberately simple (no public-suffix-list dependency) — good enough for
    the common case; multi-part TLDs like .co.uk are handled by a small
    known-suffix list below rather than a full PSL parse.
    """
    if not address:
        return ""
    domain = address.strip().lower()
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    domain = domain.strip("<>. ")

    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    two_part_suffixes = {"co.uk", "co.in", "org.uk", "gov.uk", "ac.uk", "com.au", "co.jp"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _coerce_single_date(value):
    """python-whois sometimes returns a list of dates (different registrars
    format inconsistently) — always take the earliest one."""
    if isinstance(value, list):
        value = [v for v in value if v is not None]
        return min(value) if value else None
    return value


def get_domain_intel(address: str) -> dict:
    """Returns WHOIS-derived signals for the sender's domain. Never raises —
    on any failure (unregistered domain, WHOIS server unreachable/rate-limited,
    privacy-protected registration) returns a dict with status set accordingly
    so scoring.py / advanced_security.py can treat it as 'unknown' rather than
    breaking the pipeline."""
    domain = extract_registrable_domain(address)
    if not domain or "." not in domain:
        return {"domain": domain, "status": "no_domain", "age_days": None,
                 "recently_registered": False, "registrar": None,
                 "registrant_country": None, "creation_date": None}

    try:
        w = whois.whois(domain, quiet=True, timeout=6)
        creation = _coerce_single_date(w.creation_date)
        age_days = None
        recently_registered = False
        if isinstance(creation, datetime):
            now = datetime.now(timezone.utc) if creation.tzinfo else datetime.utcnow()
            age_days = (now - creation).days
            recently_registered = age_days is not None and age_days < RECENT_REGISTRATION_DAYS

        registrar = w.registrar if isinstance(w.registrar, str) else (w.registrar[0] if w.registrar else None)
        country = getattr(w, "country", None)
        if isinstance(country, list):
            country = country[0] if country else None

        return {
            "domain": domain,
            "status": "success",
            "age_days": age_days,
            "recently_registered": recently_registered,
            "registrar": registrar,
            "registrant_country": country,
            "creation_date": creation.isoformat() if isinstance(creation, datetime) else None,
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "message": str(e),
            "age_days": None,
            "recently_registered": False,
            "registrar": None,
            "registrant_country": None,
            "creation_date": None,
        }


if __name__ == "__main__":
    import sys, json
    print(json.dumps(get_domain_intel(sys.argv[1]), indent=2, default=str))
