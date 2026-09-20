"""
language_router.py
Detects the language of an email and routes it to the right classifier.

Three-way outcome:
  "hi"     - Devanagari script present above a threshold  -> Hindi model
  "hi-en"  - romanized Hinglish detected in Latin script  -> Hindi model
  "en"     - everything else                              -> English model

Detection is deliberately dependency-free (no langdetect/fastText): a
Unicode-block ratio plus a romanized-Hindi marker lexicon. That is a few
microseconds, is fully deterministic, and — unlike a statistical language
detector — is auditable: an analyst can see exactly which markers fired.
Short phishing SMS-style text is also where statistical detectors are
weakest, which is precisely the traffic that matters here.

If phishing_model_hi.pkl has not been trained yet, routing degrades safely:
the English model still scores the email, and the Hindi keyword rule layer
still contributes, so nothing breaks — the response just carries
"hi_model_available": false.
"""

import os
import pickle
import re

_HI_MODEL = None
_HI_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model_hi.pkl")

DEVANAGARI = re.compile(r"[\u0900-\u097F]")
DEVANAGARI_RATIO_THRESHOLD = 0.10

# Romanized Hindi markers. Split into two tiers so the score reflects how
# specific the evidence is: fraud-context terms are weighted above generic
# Hindi function words, which also appear in ordinary bilingual office mail.
HINGLISH_FUNCTION_WORDS = {
    "aapka", "aapke", "aapki", "kripya", "karein", "kare", "karna", "hai", "hain",
    "nahi", "jayega", "jayegi", "gaya", "diya", "liye", "yahan", "abhi", "sabhi",
    "dhanyavaad", "dhanyavad", "namaste", "mein", "mera", "hoga", "hogi", "raha",
}
HINGLISH_FRAUD_MARKERS = {
    "turant", "khata", "khaata", "khate", "band", "jaldi", "paisa", "paise",
    "rupaye", "lakh", "inaam", "lottery", "jeeti", "bijli", "connection",
    "aadhaar", "aadhar", "pan", "kyc", "otp", "upi", "pin", "cvv", "netbanking",
    "bhejein", "daalein", "verify", "update", "block", "bakaya", "shulk", "fees",
}

# Devanagari fraud vocabulary — the rule layer that works even with no Hindi
# model trained. Kept parallel to SUSPICIOUS_KEYWORDS in scoring.py.
HINDI_FRAUD_KEYWORDS = [
    "तुरंत", "खाता बंद", "सत्यापित", "केवाईसी", "आधार", "ओटीपी", "लॉटरी",
    "इनाम", "बैंक विवरण", "क्लिक करें", "अंतिम सूचना", "संदिग्ध", "शुल्क",
    "ब्लॉक", "रिफंड", "पासवर्ड", "कार्ड नंबर",
]
HINGLISH_FRAUD_PHRASES = [
    "kyc update", "khata band", "account band", "turant", "otp share",
    "click karein", "verify karein", "link par click", "aadhaar link",
    "card block", "paisa kat", "lottery jeeti", "processing fees",
]


def _load_hi_model():
    global _HI_MODEL
    if _HI_MODEL is None:
        if not os.path.exists(_HI_MODEL_PATH):
            return None
        with open(_HI_MODEL_PATH, "rb") as f:
            _HI_MODEL = pickle.load(f)
    return _HI_MODEL


def detect_language(text: str) -> dict:
    """Returns {"language", "devanagari_ratio", "markers", "confidence"}."""
    text = text or ""
    letters = [c for c in text if c.isalpha()]
    deva = DEVANAGARI.findall(text)
    ratio = (len(deva) / len(letters)) if letters else 0.0

    if ratio >= DEVANAGARI_RATIO_THRESHOLD:
        return {
            "language": "hi",
            "devanagari_ratio": round(ratio, 3),
            "markers": [],
            "confidence": round(min(1.0, 0.6 + ratio), 2),
        }

    tokens = set(re.findall(r"[a-z']+", text.lower()))
    fraud_hits = sorted(tokens & HINGLISH_FRAUD_MARKERS)
    func_hits = sorted(tokens & HINGLISH_FUNCTION_WORDS)
    weighted = 2 * len(fraud_hits) + len(func_hits)

    if weighted >= 5 and (fraud_hits or len(func_hits) >= 3):
        return {
            "language": "hi-en",
            "devanagari_ratio": round(ratio, 3),
            "markers": (fraud_hits + func_hits)[:10],
            "confidence": round(min(0.95, 0.45 + 0.05 * weighted), 2),
        }

    return {
        "language": "en",
        "devanagari_ratio": round(ratio, 3),
        "markers": (fraud_hits + func_hits)[:10],
        "confidence": 0.8,
    }


def regional_keyword_score(text: str) -> dict:
    """
    Script-independent rule layer for Hindi/Hinglish fraud vocabulary.
    Returns a 0-25 score contribution plus the phrases that fired, so it can
    be appended to scoring.py's `reasons` list like every other rule.
    """
    lowered = (text or "").lower()
    hits = [k for k in HINDI_FRAUD_KEYWORDS if k in lowered]
    hits += [p for p in HINGLISH_FRAUD_PHRASES if p in lowered]
    return {
        "score": min(len(hits) * 6, 25),
        "hits": hits[:8],
    }


def predict_phishing_probability_multilingual(subject: str, body: str, sender: str = "") -> dict:
    """
    Drop-in multilingual replacement for
    ml_classifier.predict_phishing_probability().

    Returns:
    {
      "probability": 0.93,
      "language": "hi-en",
      "language_confidence": 0.8,
      "model_used": "hindi" | "english",
      "hi_model_available": True,
      "regional_keyword_score": 18,
      "regional_hits": ["kyc update", "turant"]
    }
    """
    from ml_classifier import predict_phishing_probability

    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    lang = detect_language(text)
    regional = regional_keyword_score(text)

    hi_model = _load_hi_model() if lang["language"] in ("hi", "hi-en") else None

    if hi_model is not None:
        proba = hi_model.predict_proba([text])[0]
        classes = list(hi_model.classes_)
        probability = float(proba[classes.index(1)])
        model_used = "hindi"
    else:
        probability = predict_phishing_probability(subject=subject, body=body, sender=sender)
        model_used = "english"

    return {
        "probability": round(probability, 3),
        "language": lang["language"],
        "language_confidence": lang["confidence"],
        "language_markers": lang["markers"],
        "model_used": model_used,
        "hi_model_available": os.path.exists(_HI_MODEL_PATH),
        "regional_keyword_score": regional["score"],
        "regional_hits": regional["hits"],
    }


if __name__ == "__main__":
    import json
    samples = [
        ("KYC update karein turant",
         "Dear customer, aapka bank khata 24 ghante me band ho jayega. Kripya turant "
         "is link par click karke KYC update karein: http://bit.ly/kyc-now"),
        ("तुरंत ध्यान दें",
         "प्रिय ग्राहक, आपका बैंक खाता बंद कर दिया जाएगा। कृपया तुरंत केवाईसी सत्यापित करें।"),
        ("Q3 planning sync",
         "Hi team, attaching the agenda for tomorrow's planning meeting. Thanks."),
    ]
    for subj, body in samples:
        print(json.dumps(predict_phishing_probability_multilingual(subj, body, "x@y.com"),
                         indent=2, ensure_ascii=False))
