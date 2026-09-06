"""
ml_classifier.py
Loads the trained phishing_model.pkl and exposes a predict function that
returns a phishing probability, used by scoring.py as the "AI/ML model" layer.
"""

import pickle
import os

_MODEL = None
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")


def _load_model():
    global _MODEL
    if _MODEL is None:
        if not os.path.exists(_MODEL_PATH):
            raise FileNotFoundError(
                "phishing_model.pkl not found. Run `python3 train_model.py` first."
            )
        with open(_MODEL_PATH, "rb") as f:
            _MODEL = pickle.load(f)
    return _MODEL


def predict_phishing_probability(subject: str, body: str, sender: str = "") -> float:
    """
    Returns a float 0.0-1.0 representing the model's confidence the email
    is phishing. Combines sender/subject/body the same way the training
    data was formatted for consistency.
    """
    model = _load_model()
    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    proba = model.predict_proba([text])[0]
    # class 1 = phishing (see generate_dataset.py labeling)
    classes = list(model.classes_)
    phishing_idx = classes.index(1)
    return float(proba[phishing_idx])


if __name__ == "__main__":
    import sys
    prob = predict_phishing_probability(
        subject="URGENT: verify your account now",
        body="Click here to confirm your password and bank details immediately.",
        sender='"Security Team" <alert@fake-bank.com>',
    )
    print(f"Phishing probability: {prob:.3f}")
