"""
train_model.py
Trains a real scikit-learn text classification model (TF-IDF + Logistic
Regression) to distinguish phishing vs legitimate emails, and saves it to disk.

Run: python3 train_model.py
Produces: phishing_model.pkl (loaded by ml_classifier.py)
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

from generate_dataset import generate_dataset


def train():
    dataset_path = "phishing_dataset.csv"
    if not os.path.exists(dataset_path):
        generate_dataset(n_per_class=400, out_path=dataset_path)

    df = pd.read_csv(dataset_path)
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000)),
    ])

    pipeline.fit(X_train, y_train)

    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Test accuracy: {acc:.3f}")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing"]))

    with open("phishing_model.pkl", "wb") as f:
        pickle.dump(pipeline, f)

    print("Model saved to phishing_model.pkl")
    return pipeline, acc


if __name__ == "__main__":
    train()
