"""
train_model_hi.py
Trains the Hindi / code-mixed Hinglish phishing classifier used by
language_router.py, and saves it to phishing_model_hi.pkl.

Same shape as train_model.py (a single sklearn Pipeline, pickled), with one
deliberate difference: the vectorizer uses character n-grams
(analyzer="char_wb", 2-5) instead of word n-grams.

Why character n-grams here — this is the technical point to make if a judge
asks why you didn't just reuse the English setup:
  * Romanized Hinglish has no fixed spelling. "khata"/"khaata"/"khatha",
    "turant"/"turnat", "jayega"/"jaayega" are the same word to a reader and
    three unrelated tokens to a word-level model. Character n-grams share
    substrings across all the spellings.
  * Devanagari is agglutinative and heavily inflected ("खाता", "खाते",
    "खातों"), so word-level features fragment there too.
  * It sidesteps the fact that neither NLTK nor sklearn ships a Hindi
    stop-word list or stemmer.

Usage:
    python3 generate_hindi_dataset.py
    python3 train_model_hi.py
"""

import os
import pickle

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DATASET_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset_hi.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model_hi.pkl")


def load_or_build_dataset() -> pd.DataFrame:
    if not os.path.exists(DATASET_PATH):
        print(f"{DATASET_PATH} not found — generating it first...")
        from generate_hindi_dataset import generate
        generate(out_path=DATASET_PATH)
    df = pd.read_csv(DATASET_PATH)
    if not {"text", "label"}.issubset(df.columns):
        raise ValueError(f"{DATASET_PATH} must have 'text' and 'label' columns")
    return df


def train():
    df = load_or_build_dataset()
    print(f"Loaded {len(df)} samples "
          f"({(df['label'] == 1).sum()} phishing / {(df['label'] == 0).sum()} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                  max_features=20000, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000)),
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print(f"\nHold-out accuracy: {accuracy_score(y_test, y_pred):.3f}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"Saved Hindi model -> {MODEL_PATH}")
    print(
        "\nNOTE for judge Q&A: this model is trained on a synthetic, "
        "template-generated Hindi/Hinglish corpus (see generate_hindi_dataset.py). "
        "The accuracy above is a same-distribution hold-out split, which on "
        "template data is optimistic by construction — present it as 'the routing "
        "and the pipeline work end to end', not as a real-world detection rate."
    )


if __name__ == "__main__":
    train()
