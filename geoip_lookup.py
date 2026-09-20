"""
geoip_lookup.py
Geolocates an IP address using the free ip-api.com JSON API (no key required).
Falls back gracefully if offline / rate-limited so the demo never crashes.

NOTE: For production / offline demo reliability, swap this for MaxMind GeoLite2
local DB (geoip2 python package) — this version is chosen for zero-setup speed.
"""

import requests


def geolocate_ip(ip: str) -> dict:
    if not ip:
        return {
            "ip": None,
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": None,
            "lon": None,
            "status": "no_ip_found",
        }

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,"
                               "proxy,hosting,mobile,lat,lon,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "org": data.get("org", "Unknown"),
                "as": data.get("as", "Unknown"),
                # ip-api's free tier flags known VPN/proxy exit points and
                # datacenter/hosting ranges directly — fed into infra_intel.py
                # alongside the static ASN keyword list and the Tor exit list.
                "is_proxy_or_vpn": bool(data.get("proxy", False)),
                "is_hosting": bool(data.get("hosting", False)),
                "is_mobile": bool(data.get("mobile", False)),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "status": "success",
            }
        else:
            return {"ip": ip, "status": "lookup_failed", "message": data.get("message", "")}
    except Exception as e:
        return {"ip": ip, "status": "error", "message": str(e)}


def check_geo_mismatch(claimed_country: str, actual_geo: dict) -> bool:
    """
    Simple heuristic: if the claimed sender domain's country (e.g. inferred
    from TLD or org name) doesn't match the actual IP's country, flag mismatch.
    In the 8-hour prototype this is a placeholder hook — extend with domain
    WHOIS lookups for a stronger signal.
    """
    if not claimed_country or actual_geo.get("status") != "success":
        return False
    return claimed_country.lower() != actual_geo.get("country", "").lower()


if __name__ == "__main__":
    import sys, json
    print(json.dumps(geolocate_ip(sys.argv[1]), indent=2))
