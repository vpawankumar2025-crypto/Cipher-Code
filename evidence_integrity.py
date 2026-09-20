"""
evidence_integrity.py
SHA-256 hashing of the raw uploaded .eml bytes at intake, plus a simple
hash-chained audit trail per case — the concrete "chain of custody"
practice this problem statement's "Forensic Intelligence Platform" name
points at.

Why this matters for a jury: a forensic tool's output is only as credible
as the guarantee that the evidence wasn't altered after capture. Hashing
the raw bytes the instant they're received, and recording that hash
immutably, is the same practice real forensic and legal chain-of-custody
procedures use (it's what "hash value" means on an evidence log). It costs
one hash computation and gives you a genuine, defensible answer to "how do
you know this hasn't been tampered with?"

This is NOT a blockchain and doesn't claim to be — SIH judges see "we used
blockchain" claims constantly and are rightly skeptical of them when the
actual mechanism is just a hash. A hash chain (each record's hash covers
the previous record's hash) gives the same tamper-evidence property
without the complexity, cost, or buzzword baggage of standing up a ledger.
Say it plainly: "SHA-256 hash of the original bytes, chained per case."

Usage:
    from evidence_integrity import hash_evidence, verify_evidence, append_chain

    record = hash_evidence(raw_bytes, filename="phishing_email.eml")
    # record = {"sha256": "...", "size_bytes": N, "hashed_at": "...iso..."}

    ok = verify_evidence(raw_bytes, record["sha256"])  # True/False

    chain_entry = append_chain(prev_hash, record["sha256"], event="ingested")
    # chain_entry["chain_hash"] links this event to everything before it
"""

import hashlib
from datetime import datetime


def hash_evidence(raw_bytes: bytes, filename: str = "") -> dict:
    """Hashes the exact bytes as received — before any parsing, decoding,
    or normalization touches them. Call this first, at upload time."""
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return {
        "sha256": digest,
        "algorithm": "SHA-256",
        "size_bytes": len(raw_bytes),
        "filename": filename,
        "hashed_at": datetime.utcnow().isoformat() + "Z",
    }


def verify_evidence(raw_bytes: bytes, expected_sha256: str) -> bool:
    """Re-hashes the given bytes and compares to a previously recorded
    hash. Returns True only on an exact match — use this to prove a
    downloaded/exported copy of the evidence still matches what was
    originally ingested."""
    return hashlib.sha256(raw_bytes).hexdigest() == (expected_sha256 or "").lower()


def append_chain(prev_chain_hash: str, evidence_sha256: str, event: str,
                 detail: str = "") -> dict:
    """
    Produces one chain-of-custody entry. Each entry's chain_hash is computed
    over (prev_chain_hash + this event's own fields), so altering any past
    entry, or reordering them, changes every chain_hash after it — the
    standard hash-chain tamper-evidence property.

    `prev_chain_hash` is "" / None for the first entry in a case's chain.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    prev = prev_chain_hash or ""
    payload = f"{prev}|{evidence_sha256}|{event}|{detail}|{timestamp}"
    chain_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "prev_chain_hash": prev,
        "evidence_sha256": evidence_sha256,
        "event": event,
        "detail": detail,
        "timestamp": timestamp,
        "chain_hash": chain_hash,
    }


def verify_chain(entries: list) -> dict:
    """
    Recomputes every chain_hash in order and confirms each one both matches
    its stored value and correctly links to the previous entry. Returns
    {"valid": True} or {"valid": False, "broken_at": <index>} pointing at
    the first entry that doesn't recompute — i.e. the first point of
    tampering or corruption, if any.
    """
    prev = ""
    for i, entry in enumerate(entries):
        payload = (f"{prev}|{entry['evidence_sha256']}|{entry['event']}|"
                  f"{entry.get('detail', '')}|{entry['timestamp']}")
        recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if recomputed != entry.get("chain_hash") or entry.get("prev_chain_hash", "") != prev:
            return {"valid": False, "broken_at": i}
        prev = entry["chain_hash"]
    return {"valid": True, "entries_verified": len(entries)}


if __name__ == "__main__":
    raw = b"From: attacker@fake-bank.com\nSubject: test\n\nbody"
    rec = hash_evidence(raw, "test.eml")
    print("hash record:", rec)
    print("verify (correct bytes):", verify_evidence(raw, rec["sha256"]))
    print("verify (tampered):", verify_evidence(raw + b"x", rec["sha256"]))

    e1 = append_chain("", rec["sha256"], "ingested", "uploaded via dashboard")
    e2 = append_chain(e1["chain_hash"], rec["sha256"], "scored", "verdict=Malicious score=88")
    e3 = append_chain(e2["chain_hash"], rec["sha256"], "report_exported", "CERT-In PDF generated")
    chain = [e1, e2, e3]
    print("chain verify (untouched):", verify_chain(chain))

    tampered = [dict(e1), dict(e2), dict(e3)]
    tampered[1]["detail"] = "verdict=Safe score=5"  # simulate tampering
    print("chain verify (tampered):", verify_chain(tampered))
