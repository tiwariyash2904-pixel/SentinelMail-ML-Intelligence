"""Quick, portable inspection tool for trained SentinelMail model artifacts.

Run from the project root: ``python models/hello.py``.
It intentionally prints metadata only, not a huge estimator representation.
"""

from pathlib import Path

import joblib


MODELS_DIR = Path(__file__).resolve().parent


def describe(name: str) -> None:
    artifact = joblib.load(MODELS_DIR / name)
    print(f"{name}: {type(artifact).__name__}")
    if hasattr(artifact, "classes_"):
        print(f"  classes: {list(artifact.classes_)}")
    if hasattr(artifact, "n_features_in_"):
        print(f"  input features: {artifact.n_features_in_}")
    if hasattr(artifact, "vocabulary_"):
        print(f"  vocabulary size: {len(artifact.vocabulary_)}")


if __name__ == "__main__":
    for artifact_name in ("struct_model.joblib", "nlp_model.joblib", "multiclass_model.joblib", "tfidf_vectorizer.joblib"):
        describe(artifact_name)
