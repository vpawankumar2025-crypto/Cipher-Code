"""
eml_parser.py
Parses a raw .eml file and extracts:
- From, To, Subject, Date
- Full Received header chain
- The true originating IP address (first external hop)
- SPF / DKIM / DMARC authentication results (from Authentication-Results header)
- Links and attachments found in the body
"""

import email
import re
from email import policy
from email.parser import BytesParser


PRIVATE_IP_PATTERNS = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"^192\.168\.",
    r"^127\.",
    r"^::1$",
    r"^fe80:",
]

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")


def is_private_ip(ip: str) -> bool:
    return any(re.match(p, ip) for p in PRIVATE_IP_PATTERNS)


def parse_eml(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    result = {
        "from": msg.get("From", "Unknown"),
        "to": msg.get("To", "Unknown"),
        "subject": msg.get("Subject", "(no subject)"),
        "date": msg.get("Date", "Unknown"),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
    }

    # --- Extract Received header chain & originating IP ---
    received_headers = msg.get_all("Received", [])
    result["received_chain"] = received_headers

    originating_ip = None
    # Walk chain from bottom (oldest/farthest hop) upward — the first
    # public IP found is the best guess for the true origin.
    for header in reversed(received_headers):
        ips_found = IP_REGEX.findall(header)
        for ip in ips_found:
            if not is_private_ip(ip):
                originating_ip = ip
                break
        if originating_ip:
            break
    result["originating_ip"] = originating_ip

    # --- Authentication-Results header (SPF/DKIM/DMARC as seen by receiving server) ---
    auth_results = msg.get_all("Authentication-Results", [])
    auth_text = " ".join(auth_results) if auth_results else ""

    def extract_result(mechanism):
        m = re.search(rf"{mechanism}=(\w+)", auth_text, re.IGNORECASE)
        return m.group(1).lower() if m else "none"

    result["spf_result"] = extract_result("spf")
    result["dkim_result"] = extract_result("dkim")
    result["dmarc_result"] = extract_result("dmarc")
    result["auth_results_raw"] = auth_text

    # --- Body text + links ---
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = ""

    result["body_text"] = body_text
    result["links"] = URL_REGEX.findall(body_text)

    # --- Attachments ---
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
    result["attachments"] = attachments

    # --- Display-name / from-address mismatch check (simple spoofing signal) ---
    from_header = result["from"]
    display_name_match = re.match(r'"?([^"<]*)"?\s*<(.+)>', from_header)
    if display_name_match:
        result["display_name"] = display_name_match.group(1).strip()
        result["from_address"] = display_name_match.group(2).strip()
    else:
        result["display_name"] = ""
        result["from_address"] = from_header.strip()

    return result


if __name__ == "__main__":
    import sys, json
    data = parse_eml(sys.argv[1])
    print(json.dumps(data, indent=2, default=str))
