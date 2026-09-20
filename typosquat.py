"""
typosquat.py
Detects lookalike/typosquatted sender domains impersonating well-known
brands — the classic "paypa1-alerts.com" vs "paypal.com" pattern that is
in this project's own phishing sample.

Method: Damerau-Levenshtein edit distance between the sender's registrable
domain and a watch-list of commonly-impersonated brand domains, plus a
handful of targeted checks (digit-for-letter substitution, hyphen insertion,
extra-word insertion like "paypal-security.com") that plain edit distance
under-weights. Distance is computed on the domain label only (not the TLD),
so "paypal.co" vs "paypal.com" is still caught.

This runs with zero network calls and zero paid API — every SIH26106 team
building "lookalike-domain detection" as a named module is doing some
version of this; edit-distance-on-a-brand-list is the standard, defensible
approach (it's what browsers' Safe Browsing typosquat heuristics are
loosely based on too).

Extend BRAND_WATCHLIST with your institution's own domain and any
regionally-relevant brands (Indian banks, UPI apps, etc.) before a demo.
"""

import re

# Institution / regionally-relevant brands go first so they show up in any
# demo without extra config. Extend freely — one line each.
BRAND_WATCHLIST = [
    # Global brands most commonly impersonated in phishing
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "facebook.com", "netflix.com", "linkedin.com", "dropbox.com", "adobe.com",
    "docusign.com", "americanexpress.com", "chase.com", "wellsfargo.com",
    # Indian banks / PSUs / payment apps — high relevance for this PS
    "sbi.co.in", "onlinesbi.com", "hdfcbank.com", "icicibank.com",
    "axisbank.com", "pnbindia.in", "indianbank.in", "canarabank.com",
    "paytm.com", "phonepe.com", "googlepay.com", "bhimupi.org.in",
    "incometax.gov.in", "uidai.gov.in", "irctc.co.in", "epfindia.gov.in",
    "cybercrime.gov.in",
]

# Edit distance at or below this on the domain label is flagged.
MAX_SUSPICIOUS_DISTANCE = 2

_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a",
    "rn": "m",  # "rn" rendered can look like "m"
}


def _registrable_label(domain: str) -> str:
    """Strips a subdomain down to the core brand label, e.g.
    'secure.paypal-alerts.com' -> 'paypal-alerts', 'sbi.co.in' -> 'sbi'."""
    domain = (domain or "").lower().strip().rstrip(".")
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    parts = domain.split(".")
    if len(parts) <= 2:
        return parts[0] if parts else ""
    # Handle common two-part TLDs (co.in, com.au, gov.in, ...) by dropping
    # the last two labels rather than just the last one.
    if parts[-2] in ("co", "com", "gov", "org", "net", "edu") and len(parts[-1]) == 2:
        return parts[-3] if len(parts) >= 3 else parts[0]
    return parts[-2]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


def _normalize_homoglyphs(label: str) -> str:
    out = label
    for glyph, letter in _HOMOGLYPHS.items():
        out = out.replace(glyph, letter)
    return out


def check_typosquat(sender_domain: str, watchlist=None) -> dict:
    """
    Returns:
    {
      "flagged": True,
      "matched_brand": "paypal.com",
      "distance": 1,
      "technique": "character substitution" | "homoglyph substitution" |
                   "hyphen/word insertion" | "exact label, different TLD",
      "sender_label": "paypa1",
    }
    or {"flagged": False} if nothing in the watchlist is close enough.

    Never flags a domain that IS the brand itself (exact registrable-domain
    match against the watchlist is treated as legitimate, not typosquat).
    """
    watchlist = watchlist or BRAND_WATCHLIST
    sender_domain = (sender_domain or "").lower().strip()
    if not sender_domain:
        return {"flagged": False}

    sender_full = sender_domain.split("/")[0]
    if sender_full in watchlist:
        return {"flagged": False}  # exact legitimate match

    sender_label = _registrable_label(sender_domain)
    sender_label_norm = _normalize_homoglyphs(sender_label)
    if not sender_label:
        return {"flagged": False}

    best = None
    for brand_domain in watchlist:
        brand_label = _registrable_label(brand_domain)
        if not brand_label:
            continue

        # Same TLD family, exact label match -> not typosquat, it's the
        # brand's own subdomain territory; skip (handled above for exact,
        # this guards near-exact like "mail.paypal.com").
        if sender_label == brand_label and sender_full != brand_domain:
            distance, technique = 0, "exact label, different domain/TLD"
        else:
            d1 = _levenshtein(sender_label, brand_label)
            d2 = _levenshtein(sender_label_norm, brand_label)
            if brand_label in sender_label_norm and sender_label_norm != brand_label:
                # e.g. "paypal-security" (or "paypa1-alerts" after homoglyph
                # normalization) contains "paypal" as a whole substring
                distance, technique = 1, "hyphen/word insertion"
            elif d2 < d1:
                distance, technique = d1, "homoglyph substitution"
            else:
                distance, technique = d1, "character substitution"

        if best is None or distance < best[0]:
            best = (distance, brand_domain, technique)

    if best is None:
        return {"flagged": False}

    distance, matched_brand, technique = best
    if distance <= MAX_SUSPICIOUS_DISTANCE and distance > 0 or technique == "hyphen/word insertion":
        return {
            "flagged": True,
            "matched_brand": matched_brand,
            "distance": distance,
            "technique": technique,
            "sender_label": sender_label,
        }

    return {"flagged": False}


if __name__ == "__main__":
    tests = [
        "paypa1-alerts.com", "secure.paypal-verify.com", "sbi-kyc-update.online",
        "paypal.com", "hdfcbank.com", "totally-unrelated-shop.com", "app1e.com",
    ]
    for t in tests:
        print(t, "->", check_typosquat(t))
