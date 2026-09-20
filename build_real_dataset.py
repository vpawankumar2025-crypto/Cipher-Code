"""
build_real_dataset.py
Builds phishing_dataset.csv from REAL email data (not synthetic).

Source 1 — Enron Spam Dataset (real corpus): 33,716 real emails —
16,545 legitimate Enron employee emails ("ham") + 17,171 real-world spam
emails, compiled by V. Metsis, I. Androutsopoulos, G. Paliouras and mirrored
at https://github.com/MWiechmann/enron_spam_data. This is a widely-cited
academic dataset (used in "Spam Filtering with Naive Bayes — Which Naive
Bayes?", CEAS 2006) — a real, defensible source for a jury, unlike a
synthetically generated one.

Source 2 — Modern phishing/BEC supplement (synthetic, clearly labeled as
such): the Enron corpus is from 1999-2001 and predates OTP codes, KYC
update scams, gift-card fraud, and other patterns common in today's
phishing/business-email-compromise attacks. generate_dataset.py's templates
fill that gap. This is a deliberate, disclosed blend — not a substitute for
the real corpus, an addition to cover attack patterns real 2001 spam
would never contain.

HONESTY NOTE FOR THE TEAM: label this to judges as what it is — "trained on
a real 34k-email academic corpus (Enron spam/ham) plus a disclosed synthetic
supplement for modern attack patterns the 2001 corpus predates." That is a
defensible, specific claim. Do not round it up to "trained on real phishing
data" without the caveat, and do not quote the hold-out accuracy from
train_model.py as a real-world detection rate — it is a hold-out score on
this blended dataset, not a benchmark against an independent test set.

Usage:
    python3 build_real_dataset.py
    # then:
    python3 train_model.py

Needs internet access to github.com / raw.githubusercontent.com to fetch the
Enron corpus zip (~15 MB). If you're offline, this script does nothing and
train_model.py will fall back to the fully-synthetic generate_dataset.py path.
"""

import csv
import io
import os
import random
import re
import zipfile

import requests

ENRON_ZIP_URL = "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip"
OUT_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")

SAMPLES_PER_CLASS_REAL = 3000     # from the real Enron corpus
SAMPLES_PER_CLASS_MODERN = 500    # from the disclosed synthetic supplement
MAX_MESSAGE_CHARS = 900           # keeps the shipped CSV a few MB, not tens of MB

random.seed(42)


def _clean(text: str) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:MAX_MESSAGE_CHARS]


def fetch_enron_sample():
    """Downloads the real Enron spam/ham corpus and returns a balanced,
    cleaned sample as a list of (text, label) tuples. Returns None if the
    download fails (offline / blocked network) so the caller can fall back
    gracefully instead of crashing."""
    print(f"Downloading real Enron spam/ham corpus from {ENRON_ZIP_URL} ...")
    try:
        import pandas as pd  # local import: only needed on this path
        resp = requests.get(ENRON_ZIP_URL, timeout=30)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_name = next(n for n in zf.namelist() if n.endswith(".csv"))
            with zf.open(csv_name) as f:
                df = pd.read_csv(f)
    except Exception as e:
        print(f"Could not download the real corpus ({e}). "
              f"Falling back to the fully-synthetic dataset instead.")
        return None

    df["Subject"] = df["Subject"].fillna("")
    df["Message"] = df["Message"].fillna("")
    df = df[(df["Message"].str.strip() != "") | (df["Subject"].str.strip() != "")]
    df["text"] = "Subject: " + df["Subject"].map(_clean) + "\n\n" + df["Message"].map(_clean)
    df["label"] = (df["Spam/Ham"] == "spam").astype(int)

    spam = df[df["label"] == 1].sample(n=min(SAMPLES_PER_CLASS_REAL, (df["label"] == 1).sum()), random_state=42)
    ham = df[df["label"] == 0].sample(n=min(SAMPLES_PER_CLASS_REAL, (df["label"] == 0).sum()), random_state=42)
    print(f"Sampled {len(spam)} real spam + {len(ham)} real legitimate emails "
          f"from {len(df)} total Enron corpus rows.")
    return list(zip(spam["text"], spam["label"])) + list(zip(ham["text"], ham["label"]))


def modern_supplement_sample():
    """Disclosed synthetic supplement for modern phishing/BEC patterns
    (OTP, KYC, gift-card scams) that the 1999-2001 Enron corpus predates."""
    from generate_dataset import make_phishing_sample, make_legit_sample
    rows = []
    for _ in range(SAMPLES_PER_CLASS_MODERN):
        rows.append(make_phishing_sample())
        rows.append(make_legit_sample())
    return rows


def build(out_path: str = OUT_PATH):
    rows = fetch_enron_sample()
    if rows is None:
        # Fully offline fallback: synthetic-only, same as the original
        # prototype. Still produces a working (if less defensible) dataset.
        from generate_dataset import generate_dataset
        generate_dataset(n_per_class=400, out_path=out_path)
        print("WARNING: built from synthetic data only (no internet to fetch "
              "the real corpus). Re-run this script with internet access "
              "before demo day if at all possible.")
        return out_path

    rows += modern_supplement_sample()
    random.shuffle(rows)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    n_phish = sum(1 for _, label in rows if label == 1)
    print(f"Wrote {len(rows)} rows -> {out_path} "
          f"({n_phish} phishing/spam, {len(rows) - n_phish} legitimate)")
    return out_path


if __name__ == "__main__":
    build()
