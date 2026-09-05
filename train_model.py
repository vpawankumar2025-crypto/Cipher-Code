"""
train_model.py
Trains the phishing-vs-legitimate email classifier used by ml_classifier.py
and saves it to phishing_model.pkl.

Pipeline: TfidfVectorizer -> LogisticRegression, trained and pickled as a
single sklearn Pipeline object, so ml_classifier.py can call
model.predict_proba([raw_text]) directly without a separate vectorizing step.

Usage:
    python3 train_model.py

If phishing_dataset.csv is missing, it is generated first via
generate_dataset.py (synthetic data — see README's honesty note about
swapping this for the real Kaggle/SpamAssassin corpus).
"""

import os
import pickle

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score

DATASET_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")


def load_or_build_dataset() -> pd.DataFrame:
    if not os.path.exists(DATASET_PATH):
        print(f"{DATASET_PATH} not found — generating synthetic dataset first...")
        from generate_dataset import generate_dataset
        generate_dataset(out_path=DATASET_PATH)

    df = pd.read_csv(DATASET_PATH)
    if not {"text", "label"}.issubset(df.columns):
        raise ValueError(
            f"{DATASET_PATH} must have 'text' and 'label' columns "
            f"(label 1 = phishing, 0 = legitimate). Found: {list(df.columns)}"
        )
    return df


def train():
    df = load_or_build_dataset()
    print(f"Loaded {len(df)} samples "
          f"({(df['label'] == 1).sum()} phishing / {(df['label'] == 0).sum()} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000)),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nHold-out accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"Saved trained model -> {MODEL_PATH}")

    print(
        "\nNOTE: if phishing_dataset.csv is still the synthetic generator output, "
        "this accuracy is expected to look very high and is NOT a number to quote "
        "to judges as real-world performance -- see README's honesty note. Swap in "
        "the real Kaggle Phishing Email Dataset / SpamAssassin corpus and re-run "
        "this script for a defensible number."
    )


if __name__ == "__main__":
    train()
