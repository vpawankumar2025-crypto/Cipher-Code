"""
threat_intel.py
Checks URLs against VirusTotal and PhishTank threat-intelligence sources.

Requires an environment variable VT_API_KEY for VirusTotal (free tier available
at virustotal.com/gui/join-us). Without a key, this gracefully returns
"unchecked" rather than crashing, so the pipeline still runs end-to-end.

PhishTank's public API does not require a key for basic lookups.
"""

import os
import requests
import hashlib

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3/urls"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


def check_url_virustotal(url: str) -> dict:
    if not VT_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "malicious": None}

    try:
        url_id = hashlib.sha256(url.encode()).hexdigest()
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"{VT_BASE_URL}/{url_id}", headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            return {
                "source": "virustotal",
                "status": "checked",
                "malicious": malicious_count > 0,
                "malicious_count": malicious_count,
                "stats": stats,
            }
        elif resp.status_code == 404:
            return {"source": "virustotal", "status": "not_in_database", "malicious": None}
        else:
            return {"source": "virustotal", "status": f"error_{resp.status_code}", "malicious": None}
    except Exception as e:
        return {"source": "virustotal", "status": "error", "message": str(e), "malicious": None}


def check_url_phishtank(url: str) -> dict:
    try:
        resp = requests.post(
            PHISHTANK_URL,
            data={"url": url, "format": "json"},
            headers={"User-Agent": "phishtank/SentinelMailAI"},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", {})
            return {
                "source": "phishtank",
                "status": "checked",
                "malicious": results.get("valid") and results.get("in_database", False),
            }
        return {"source": "phishtank", "status": f"error_{resp.status_code}", "malicious": None}
    except Exception as e:
        return {"source": "phishtank", "status": "error", "message": str(e), "malicious": None}


def check_links(links: list) -> dict:
    """
    Runs all links through both threat-intel sources.
    Returns a summary: total links checked, how many flagged malicious,
    and per-link details.
    """
    details = []
    malicious_count = 0

    for url in links[:10]:  # cap to avoid rate limits during a live demo
        vt_result = check_url_virustotal(url)
        pt_result = check_url_phishtank(url)
        is_malicious = bool(vt_result.get("malicious")) or bool(pt_result.get("malicious"))
        if is_malicious:
            malicious_count += 1
        details.append({"url": url, "virustotal": vt_result, "phishtank": pt_result, "malicious": is_malicious})

    return {
        "total_checked": len(details),
        "malicious_count": malicious_count,
        "details": details,
        "vt_key_configured": bool(VT_API_KEY),
    }


if __name__ == "__main__":
    result = check_links(["http://bit.ly/paypal-verify-now"])
    import json
    print(json.dumps(result, indent=2, default=str))
