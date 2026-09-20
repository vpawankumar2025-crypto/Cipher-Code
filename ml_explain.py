"""
ml_explain.py
Turns the TF-IDF + Logistic Regression verdict from ml_classifier.py into a
human-readable "why".

For a linear model on TF-IDF features the contribution of every term that
actually appeared in this email is exactly:

    contribution(term) = tfidf_value(term) * coefficient(term)

Summed over all present terms plus the intercept, that IS the model's raw
decision value (log-odds) -- so this is not an approximation or a post-hoc
guess like LIME/SHAP would be. It is the model's own arithmetic, read back
out. That is the sentence to say to a jury when they ask "is this a black
box?".

Cost: one extra .transform() call (microseconds). No extra model, no
sampling, no perturbation.

Usage:
    from ml_explain import explain_prediction
    explain_prediction(subject, body, sender)
"""

import numpy as np

from ml_classifier import _load_model


def _split_pipeline(model):
    """Returns (vectorizer, classifier) or (None, None) if the pickle is not
    the expected TfidfVectorizer -> LogisticRegression pipeline."""
    try:
        steps = dict(model.named_steps)
    except AttributeError:
        return None, None
    vec = steps.get("tfidf")
    clf = steps.get("clf")
    if vec is None or clf is None or not hasattr(clf, "coef_"):
        return None, None
    return vec, clf


def explain_prediction(subject: str, body: str, sender: str = "", top_n: int = 8) -> dict:
    """
    Returns the terms that pushed this specific email toward 'phishing' and
    toward 'legitimate', with their signed contributions to the model's
    log-odds and their share of the total phishing-side evidence.

    Shape:
    {
      "available": True,
      "phishing_terms": [{"term": "verify account", "contribution": 0.41, "share_pct": 18.2}, ...],
      "safe_terms":     [{"term": "meeting", "contribution": -0.22, "share_pct": 11.0}, ...],
      "decision_value": 1.83,        # log-odds, intercept included
      "intercept": 0.29,
      "terms_considered": 47,        # distinct model features present in this email
      "sentence": "Flagged mainly on: verify account, urgent, bank details."
    }
    """
    model = _load_model()
    vec, clf = _split_pipeline(model)
    if vec is None:
        return {"available": False, "reason": "Model is not a TF-IDF + linear pipeline; "
                                              "term-level attribution is not defined for it."}

    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    X = vec.transform([text])
    names = vec.get_feature_names_out()

    # Binary LogisticRegression stores a single coefficient row, oriented
    # toward classes_[1]. Guard the orientation rather than assuming it, so a
    # retrain that flips the label order can't silently invert the explanation.
    coef = clf.coef_[0]
    intercept = float(clf.intercept_[0])
    classes = list(clf.classes_)
    if len(classes) == 2 and classes[1] != 1:
        coef = -coef
        intercept = -intercept

    present = X.nonzero()[1]
    contributions = []
    for i in present:
        contributions.append((float(X[0, i]) * float(coef[i]), str(names[i])))

    contributions.sort(reverse=True)
    positive = [c for c in contributions if c[0] > 0]
    negative = [c for c in contributions if c[0] < 0]

    pos_total = sum(c[0] for c in positive) or 1.0
    neg_total = sum(abs(c[0]) for c in negative) or 1.0

    phishing_terms = [
        {"term": term, "contribution": round(val, 4), "share_pct": round(100 * val / pos_total, 1)}
        for val, term in positive[:top_n]
    ]
    safe_terms = [
        {"term": term, "contribution": round(val, 4), "share_pct": round(100 * abs(val) / neg_total, 1)}
        for val, term in sorted(negative)[:top_n]
    ]

    decision_value = float(sum(c[0] for c in contributions) + intercept)

    if phishing_terms:
        top_words = ", ".join(t["term"] for t in phishing_terms[:3])
        sentence = f"Flagged mainly on the language: {top_words}."
    elif safe_terms:
        top_words = ", ".join(t["term"] for t in safe_terms[:3])
        sentence = f"Read as legitimate mainly on the language: {top_words}."
    else:
        sentence = "No recognised vocabulary from the training data appeared in this email."

    return {
        "available": True,
        "phishing_terms": phishing_terms,
        "safe_terms": safe_terms,
        "decision_value": round(decision_value, 4),
        "intercept": round(intercept, 4),
        "terms_considered": int(len(contributions)),
        "sentence": sentence,
    }


def highlight_spans(body: str, phishing_terms: list, max_terms: int = 12) -> list:
    """
    Optional helper for the UI: returns the character offsets of each flagged
    term inside the body, so the dashboard can highlight them in the rendered
    email instead of only listing them. Case-insensitive, first occurrence
    only, skips terms that don't literally appear (n-grams are stemmed/
    tokenised, so some won't).
    """
    spans = []
    lowered = (body or "").lower()
    for item in (phishing_terms or [])[:max_terms]:
        term = item.get("term", "")
        if not term:
            continue
        idx = lowered.find(term.lower())
        if idx >= 0:
            spans.append({"term": term, "start": idx, "end": idx + len(term),
                          "share_pct": item.get("share_pct", 0)})
    return sorted(spans, key=lambda s: s["start"])


if __name__ == "__main__":
    import json
    out = explain_prediction(
        subject="URGENT: verify your account now",
        body="Click here to confirm your password and bank details immediately "
             "or your account will be suspended.",
        sender='"Security Team" <alert@fake-bank.com>',
    )
    print(json.dumps(out, indent=2))
