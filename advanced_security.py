"""Advanced defensive email-security enrichment for SentinelMail AI V2.

All enrichment is passive/local: it analyzes already-parsed email data and,
when possible, performs lightweight DNS lookups. It does not fetch or execute
email links.
"""
import ipaddress
import re
import socket
from collections import Counter
from datetime import datetime
from email.utils import parseaddr
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".gq", ".tk", ".ml", ".cf"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com"},
}


def _domain_from_value(value: str) -> str:
    value = value or ""
    addr = parseaddr(value)[1]
    if "@" in addr:
        return addr.rsplit("@", 1)[1].lower().strip().strip(">")
    try:
        host = urlparse(value).hostname
        return (host or "").lower()
    except Exception:
        return ""


def _safe_dns(domain: str) -> dict:
    if not domain:
        return {"resolved": False, "addresses": [], "mx": False}
    addresses = []
    try:
        for item in socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM):
            addr = item[4][0]
            if addr not in addresses:
                addresses.append(addr)
            if len(addresses) >= 4:
                break
    except Exception:
        pass
    return {"resolved": bool(addresses), "addresses": addresses, "mx": None}


def extract_iocs(parsed: dict) -> dict:
    body = parsed.get("body_text", "") or ""
    links = parsed.get("links", []) or []
    text = "\n".join([parsed.get("subject", "") or "", body])
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))
    emails = sorted(set(re.findall(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I)))
    domains = set()
    for link in links:
        try:
            host = urlparse(link).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    sender_domain = _domain_from_value(parsed.get("from", ""))
    if sender_domain:
        domains.add(sender_domain)
    hashes = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b", text)))
    return {
        "ips": ips[:50],
        "domains": sorted(domains)[:50],
        "urls": links[:50],
        "email_addresses": emails[:50],
        "hashes": hashes[:50],
    }


def analyze_urls(parsed: dict) -> list:
    results = []
    for url in (parsed.get("links", []) or [])[:20]:
        try:
            p = urlparse(url)
            host = (p.hostname or "").lower()
            flags = []
            if p.scheme != "https":
                flags.append("not_https")
            if host in SHORTENERS or any(host.endswith("." + d) for d in SHORTENERS):
                flags.append("url_shortener")
            if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                flags.append("suspicious_tld")
            if "@" in p.netloc:
                flags.append("userinfo_in_url")
            if host.startswith("xn--") or ".xn--" in host:
                flags.append("punycode_domain")
            if len(url) > 180:
                flags.append("very_long_url")
            subdomains = host.count(".")
            if subdomains >= 4:
                flags.append("deep_subdomain")
            score = min(100, len(flags) * 18)
            results.append({"url": url, "domain": host, "flags": flags, "risk_score": score})
        except Exception:
            results.append({"url": url, "domain": "", "flags": ["malformed_url"], "risk_score": 35})
    return results


def header_forensics(parsed: dict) -> dict:
    from_domain = _domain_from_value(parsed.get("from", ""))
    reply_domain = _domain_from_value(parsed.get("reply_to", ""))
    return_domain = _domain_from_value(parsed.get("return_path", ""))
    chain = parsed.get("received_chain", []) or []
    findings = []
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append("Reply-To domain differs from From domain")
    if return_domain and from_domain and return_domain != from_domain:
        findings.append("Return-Path domain differs from From domain")
    if len(chain) == 0:
        findings.append("No Received header chain available")
    if len(chain) >= 5:
        findings.append(f"Long Received chain detected ({len(chain)} hops)")
    auth = parsed.get("auth_results_raw", "") or ""
    if not auth:
        findings.append("Authentication-Results header is absent")
    checks = {
        "spf": (parsed.get("spf_result") or "none").lower(),
        "dkim": (parsed.get("dkim_result") or "none").lower(),
        "dmarc": (parsed.get("dmarc_result") or "none").lower(),
    }
    failures = [k.upper() for k, v in checks.items() if v == "fail"]
    if failures:
        findings.append("Authentication failure: " + ", ".join(failures))
    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "received_hops": len(chain),
        "authentication": checks,
        "findings": findings,
        "header_risk": min(100, len(findings) * 18 + len(failures) * 8),
    }


def domain_risk(parsed: dict, url_results: list) -> dict:
    sender_domain = _domain_from_value(parsed.get("from", ""))
    url_domains = sorted({r["domain"] for r in url_results if r.get("domain")})
    flags = []
    if sender_domain:
        dns = _safe_dns(sender_domain)
        if not dns["resolved"]:
            flags.append("sender_domain_does_not_resolve")
    else:
        dns = {"resolved": False, "addresses": [], "mx": None}
        flags.append("sender_domain_unavailable")
    for domain in url_domains:
        if any(domain == d or domain.endswith("." + d) for d in SHORTENERS):
            flags.append(f"shortened_url_domain:{domain}")
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            flags.append(f"suspicious_tld:{domain}")
        if domain.startswith("xn--") or ".xn--" in domain:
            flags.append(f"punycode:{domain}")
    # Brand impersonation: the visible sender text mentions a known brand but
    # the actual sender domain is not one of the brand's legitimate domains.
    display = (parsed.get("display_name", "") or "").lower()
    for brand, legit in BRAND_DOMAINS.items():
        if brand in display and sender_domain and not any(sender_domain == d or sender_domain.endswith("." + d) for d in legit):
            flags.append(f"possible_{brand}_impersonation")
    return {
        "sender_domain": sender_domain,
        "url_domains": url_domains,
        "dns": dns,
        "flags": flags,
        "risk_score": min(100, len(flags) * 20),
    }


def explainable_analysis(parsed: dict, geo: dict, verdict: dict, threat_intel: dict) -> dict:
    urls = analyze_urls(parsed)
    headers = header_forensics(parsed)
    domains = domain_risk(parsed, urls)
    iocs = extract_iocs(parsed)
    ti_hits = int(threat_intel.get("malicious_count", 0) or 0)
    attachment_count = len(parsed.get("attachments", []) or [])
    url_risk = round(sum(x["risk_score"] for x in urls) / len(urls)) if urls else 0
    auth_risk = headers["header_risk"]
    content_risk = round(float(verdict.get("ml_probability", 0)) * 100)
    threat_risk = min(100, ti_hits * 50)
    attachment_risk = 0
    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".jar", ".msi")
    risky = [a for a in parsed.get("attachments", []) if str(a).lower().endswith(risky_ext)]
    if risky:
        attachment_risk = min(100, 35 + len(risky) * 20)
    geo_risk = 0 if geo.get("status") == "success" else (15 if parsed.get("originating_ip") else 5)

    # Infrastructure correlation (VPN/Tor/cloud-hosting) and WHOIS domain-age
    # intel were already computed once in scoring.py — reused here rather
    # than repeating the Tor-list fetch / WHOIS lookup a second time per case.
    infra = verdict.get("infra_intel", {}) or {}
    domain_info = verdict.get("domain_intel", {}) or {}
    infra_risk = min(100, domains["risk_score"] + geo_risk + infra.get("risk_contribution", 0))
    whois_risk = 20 if domain_info.get("recently_registered") else 0

    breakdown = [
        {"category": "AI content", "score": content_risk, "weight": 30},
        {"category": "Header & auth", "score": auth_risk, "weight": 20},
        {"category": "URL risk", "score": url_risk, "weight": 15},
        {"category": "Threat intel", "score": threat_risk, "weight": 15},
        {"category": "Attachments", "score": attachment_risk, "weight": 5},
        {"category": "Infrastructure", "score": infra_risk, "weight": 10},
        {"category": "Domain registration", "score": whois_risk, "weight": 5},
    ]
    drivers = []
    for item in sorted(breakdown, key=lambda x: x["score"] * x["weight"], reverse=True):
        if item["score"] >= 30:
            drivers.append(f"{item['category']} contributed a {item['score']}/100 risk signal")
    if headers["findings"]:
        drivers.extend(headers["findings"][:3])
    if domains["flags"]:
        drivers.extend([f.replace("_", " ") for f in domains["flags"][:3]])
    if infra.get("flags"):
        drivers.extend(infra["flags"][:2])
    effective_verdict = verdict.get("verdict", "Safe")
    summary = (
        f"{effective_verdict} email with a {verdict.get('score', 0)}/100 composite risk score. "
        f"The strongest evidence comes from {drivers[0].lower() if drivers else 'the combined baseline signals'}."
    )
    return {
        "version": "2.1",
        "summary": summary,
        "risk_breakdown": breakdown,
        "key_drivers": drivers[:8],
        "iocs": iocs,
        "url_analysis": urls,
        "header_forensics": headers,
        "domain_risk": domains,
        "attachment_analysis": {"count": attachment_count, "risky": risky, "risk_score": attachment_risk},
        "geo_signal": {"status": geo.get("status"), "country": geo.get("country"), "city": geo.get("city"), "ip": parsed.get("originating_ip"), "risk_score": geo_risk},
        "infra_intel": infra,
        "domain_intel": domain_info,
        "threat_intel": {"malicious_count": ti_hits, "sources": [d.get("virustotal", {}).get("source") for d in threat_intel.get("details", [])]},
        "timeline": _timeline(parsed, verdict, ti_hits),
        "graph": _graph(parsed, iocs, urls, threat_intel, infra, domain_info),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def _timeline(parsed: dict, verdict: dict, ti_hits: int) -> list:
    events = []
    if parsed.get("date"):
        events.append({"stage": "Message date", "detail": str(parsed["date"]), "severity": "info"})
    if parsed.get("originating_ip"):
        events.append({"stage": "Origin identified", "detail": f"IP {parsed['originating_ip']}", "severity": "info"})
    events.append({"stage": "Authentication", "detail": f"SPF {parsed.get('spf_result','none')} · DKIM {parsed.get('dkim_result','none')} · DMARC {parsed.get('dmarc_result','none')}", "severity": "warning" if any((parsed.get(k) or '').lower() == 'fail' for k in ('spf_result','dkim_result','dmarc_result')) else "info"})
    if parsed.get("links"):
        events.append({"stage": "URL enrichment", "detail": f"Analyzed {len(parsed['links'])} URL(s)", "severity": "warning" if ti_hits else "info"})
    if ti_hits:
        events.append({"stage": "Threat intelligence", "detail": f"{ti_hits} malicious indicator(s) confirmed", "severity": "critical"})
    events.append({"stage": "Final verdict", "detail": f"{verdict.get('verdict')} · {verdict.get('score', 0)}/100", "severity": "critical" if verdict.get('verdict') == 'Malicious' else "warning" if verdict.get('verdict') == 'Suspicious' else "success"})
    return events


def _graph(parsed: dict, iocs: dict, urls: list, threat_intel: dict, infra: dict = None, domain_info: dict = None) -> dict:
    infra = infra or {}
    domain_info = domain_info or {}
    nodes = [{"id": "email", "label": "Email", "type": "email"}]
    edges = []
    sender = _domain_from_value(parsed.get("from", ""))
    if sender:
        nodes.append({"id": "sender-domain", "label": sender, "type": "domain"})
        edges.append({"source": "email", "target": "sender-domain", "label": "sent by"})
        if domain_info.get("status") == "success":
            age_label = (f"{domain_info['age_days']}d old" if domain_info.get("age_days") is not None
                         else "age unknown")
            nodes.append({"id": "whois", "label": f"WHOIS: {age_label}", "type": "whois",
                          "risk": 80 if domain_info.get("recently_registered") else 10})
            edges.append({"source": "sender-domain", "target": "whois", "label": "registered via " + (domain_info.get("registrar") or "?")})
    if parsed.get("originating_ip"):
        nodes.append({"id": "origin-ip", "label": parsed["originating_ip"], "type": "ip"})
        edges.append({"source": "sender-domain", "target": "origin-ip", "label": "infrastructure"})
        if infra.get("is_tor_exit_node") or infra.get("is_proxy_or_vpn") or infra.get("matched_hosting_provider"):
            label = ("Tor exit node" if infra.get("is_tor_exit_node")
                     else "VPN/Proxy" if infra.get("is_proxy_or_vpn")
                     else f"Hosting: {infra.get('matched_hosting_provider')}")
            nodes.append({"id": "infra-flag", "label": label, "type": "infra", "risk": 90})
            edges.append({"source": "origin-ip", "target": "infra-flag", "label": "infrastructure signal"})
    for idx, item in enumerate(urls[:6]):
        node_id = f"url-{idx}"
        nodes.append({"id": node_id, "label": item.get("domain") or "URL", "type": "url", "risk": item.get("risk_score", 0)})
        edges.append({"source": "email", "target": node_id, "label": "contains URL"})
        if item.get("domain") and item.get("domain") != sender:
            domain_id = f"domain-{idx}"
            nodes.append({"id": domain_id, "label": item["domain"], "type": "domain", "risk": item.get("risk_score", 0)})
            edges.append({"source": node_id, "target": domain_id, "label": "resolves to"})
    for idx, h in enumerate(iocs.get("hashes", [])[:4]):
        node_id = f"hash-{idx}"
        nodes.append({"id": node_id, "label": h[:12] + "…", "type": "hash"})
        edges.append({"source": "email", "target": node_id, "label": "IOC"})
    if threat_intel.get("malicious_count", 0):
        nodes.append({"id": "intel", "label": "Threat Intel", "type": "intel", "risk": 100})
        edges.append({"source": "email", "target": "intel", "label": "confirmed hit"})
    return {"nodes": nodes, "edges": edges}
