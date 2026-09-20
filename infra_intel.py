"""
infra_intel.py
Correlates the sender's originating IP against known VPN/proxy, Tor, and
cloud-hosting/datacenter infrastructure — the "correlation with VPN, TOR,
open relay, botnet, or cloud-hosted infrastructure indicators" component
named explicitly in the SIH26106 brief.

Three independent signals are combined so the feature still works if any
one of them is unreachable/rate-limited during a live demo:

1. ip-api.com's own `proxy` / `hosting` flags (see geoip_lookup.py) — fast,
   no extra network round trip, but coverage varies by IP.
2. A live Tor exit-node list from the Tor Project's official bulk endpoint,
   cached in-memory and refreshed periodically so repeated lookups during a
   demo don't re-fetch it every time.
3. A static keyword list of major cloud/hosting providers (AWS, Azure, GCP,
   OVH, DigitalOcean, Hetzner, Alibaba Cloud, etc.), matched against the
   ISP/org/AS string ip-api.com already returns. Legitimate mail is almost
   never sent directly from a raw cloud IP (it goes through a mail
   provider's dedicated sending infra) — so "claims to be a bank, but the
   IP is an AWS EC2 address" is a meaningful red flag on its own, distinct
   from a formal VPN/proxy detection.

There is no free, reliable public "botnet IP" list — sources with any real
coverage require a paid feed (Spamhaus, AbuseIPDB, etc.). Rather than fake
that signal, this module is explicit about the gap (see `botnet_checked`
in the returned dict) so the team can name it honestly if a judge asks,
and can plug in AbuseIPDB (already listed as a possible upgrade in
threat_intel.py's pattern) if they get an API key before demo day.
"""

import re
import time

import requests

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_TOR_CACHE = {"ips": set(), "fetched_at": 0}
_TOR_CACHE_TTL_SECONDS = 6 * 60 * 60  # refresh at most every 6 hours

# Substring match against ip-api's `isp`/`org`/`as` fields. Deliberately a
# plain keyword list (no ASN database dependency) so this works offline
# using whatever geoip_lookup.py already returned.
HOSTING_PROVIDER_KEYWORDS = [
    "amazon", "aws", "ec2", "amazonaws",
    "google cloud", "google llc", "gcp",
    "microsoft azure", "azure",
    "digitalocean", "digital ocean",
    "linode", "akamai linode",
    "ovh", "ovhcloud",
    "hetzner",
    "alibaba", "aliyun",
    "vultr",
    "contabo",
    "oracle cloud",
    "hostinger",
    "godaddy",
    "cloudflare",
    "leaseweb",
    "scaleway",
]


def _refresh_tor_exit_list():
    """Best-effort refresh of the Tor exit-node cache. Silently keeps
    whatever was cached before (or an empty set on first run) if the fetch
    fails — a stale/missing Tor list should never break the pipeline."""
    now = time.time()
    if now - _TOR_CACHE["fetched_at"] < _TOR_CACHE_TTL_SECONDS and _TOR_CACHE["ips"]:
        return
    try:
        resp = requests.get(TOR_EXIT_LIST_URL, timeout=5)
        if resp.status_code == 200:
            ips = {line.strip() for line in resp.text.splitlines()
                   if line.strip() and not line.startswith("#")}
            if ips:
                _TOR_CACHE["ips"] = ips
                _TOR_CACHE["fetched_at"] = now
    except Exception:
        pass  # keep previous cache (possibly empty) — never raise


def _is_hosting_provider(text: str) -> str:
    """Returns the matched provider keyword, or '' if none matched."""
    if not text:
        return ""
    lowered = text.lower()
    for kw in HOSTING_PROVIDER_KEYWORDS:
        if kw in lowered:
            return kw
    return ""


def analyze_infrastructure(ip: str, geo: dict) -> dict:
    """geo is the dict already returned by geoip_lookup.geolocate_ip() for
    this same IP — reused here instead of re-fetching so this stays a pure
    correlation step with no extra required network call beyond the Tor
    list (which itself degrades to 'unknown' offline)."""
    geo = geo or {}
    result = {
        "ip": ip,
        "is_tor_exit_node": False,
        "is_proxy_or_vpn": bool(geo.get("is_proxy_or_vpn", False)),
        "is_cloud_hosting": bool(geo.get("is_hosting", False)),
        "matched_hosting_provider": "",
        "botnet_checked": False,   # honestly disclosed gap — see module docstring
        "flags": [],
        "risk_contribution": 0,
    }
    if not ip:
        return result

    _refresh_tor_exit_list()
    if ip in _TOR_CACHE["ips"]:
        result["is_tor_exit_node"] = True
        result["flags"].append("Originating IP is a known Tor exit node")
        result["risk_contribution"] += 25

    if result["is_proxy_or_vpn"]:
        result["flags"].append("IP intelligence flags this address as a known proxy/VPN endpoint")
        result["risk_contribution"] += 15

    provider_text = " ".join(str(geo.get(k, "")) for k in ("isp", "org", "as"))
    matched = _is_hosting_provider(provider_text)
    if matched or result["is_cloud_hosting"]:
        result["matched_hosting_provider"] = matched or (geo.get("org") or geo.get("isp") or "unknown provider")
        result["flags"].append(
            f"Sender IP belongs to cloud/hosting infrastructure ({result['matched_hosting_provider']}) "
            f"rather than a dedicated mail-sending range — unusual for legitimate corporate mail"
        )
        result["risk_contribution"] += 10

    result["risk_contribution"] = min(result["risk_contribution"], 40)
    return result


if __name__ == "__main__":
    import sys, json
    from geoip_lookup import geolocate_ip
    test_ip = sys.argv[1]
    geo = geolocate_ip(test_ip)
    print(json.dumps(analyze_infrastructure(test_ip, geo), indent=2, default=str))
