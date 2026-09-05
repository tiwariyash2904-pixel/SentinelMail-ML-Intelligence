"""
train.py
--------
Trains two complementary models and saves them to models/:

1. Structured model  -- GradientBoostingClassifier on header/URL/attachment/
   text-signal features (features.py). Fast, robust, and its
   feature_importances_ double as the basis for explanations.
2. NLP model         -- TF-IDF + Logistic Regression on subject+body text.
   (A transformer like DistilBERT is a drop-in upgrade later -- see
   README -- but needs internet/GPU that this sandbox doesn't have.)

Run: python3 src/train.py
"""

import argparse
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from features import build_feature_frame, get_text_series, STRUCTURED_FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYNTHETIC_DATA_PATH = os.path.join(BASE_DIR, "data", "emails_dataset.csv")
HYBRID_DATA_PATH = os.path.join(BASE_DIR, "data", "hybrid_emails_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def load_data(path: str):
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")
    return df


def main(dataset_path: str | None = None):
    dataset_path = dataset_path or (HYBRID_DATA_PATH if os.path.exists(HYBRID_DATA_PATH) else SYNTHETIC_DATA_PATH)
    df = load_data(dataset_path)

    # Binary "malicious vs legitimate" target drives the risk score;
    # the multiclass label is kept too, for the forensic report's attack-type field.
    y_multiclass = df["label"]
    y_binary = (df["label"] != "legitimate").astype(int)

    X_struct = build_feature_frame(df)
    X_text = get_text_series(df)

    (X_struct_train, X_struct_test,
     X_text_train, X_text_test,
     y_train, y_test,
     y_mc_train, y_mc_test) = train_test_split(
        X_struct, X_text, y_binary, y_multiclass,
        # Preserve every attack type in the test set, not just the binary ratio.
        test_size=0.2, random_state=42, stratify=y_multiclass,
    )

    # --- 1. Structured model ---
    struct_model = GradientBoostingClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.1, random_state=42
    )
    struct_model.fit(X_struct_train, y_train)
    struct_probs = struct_model.predict_proba(X_struct_test)[:, 1]

    # --- 2. NLP model ---
    vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")
    Xt_train = vectorizer.fit_transform(X_text_train)
    Xt_test = vectorizer.transform(X_text_test)

    nlp_model = LogisticRegression(max_iter=1000, C=1.0)
    nlp_model.fit(Xt_train, y_train)
    nlp_probs = nlp_model.predict_proba(Xt_test)[:, 1]

    # --- 3. Multiclass model (attack-type classifier, for the forensic report) ---
    le = LabelEncoder()
    y_mc_train_enc = le.fit_transform(y_mc_train)
    y_mc_test_enc = le.transform(y_mc_test)
    multiclass_model = GradientBoostingClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.1, random_state=42
    )
    multiclass_model.fit(X_struct_train, y_mc_train_enc)
    mc_preds = multiclass_model.predict(X_struct_test)

    # --- 4. Ensemble: weighted average of structured + NLP probabilities ---
    W_STRUCT, W_NLP = 0.6, 0.4
    ensemble_probs = W_STRUCT * struct_probs + W_NLP * nlp_probs
    ensemble_preds = (ensemble_probs >= 0.5).astype(int)

    # --- Evaluation ---
    report = classification_report(y_test, ensemble_preds, target_names=["legitimate", "malicious"], output_dict=True)
    cm = confusion_matrix(y_test, ensemble_preds).tolist()
    auc = roc_auc_score(y_test, ensemble_probs)

    mc_report = classification_report(y_mc_test_enc, mc_preds, target_names=le.classes_, output_dict=True)

    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    joblib.dump(struct_model, os.path.join(MODELS_DIR, "struct_model.joblib"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "tfidf_vectorizer.joblib"))
    joblib.dump(nlp_model, os.path.join(MODELS_DIR, "nlp_model.joblib"))
    joblib.dump(multiclass_model, os.path.join(MODELS_DIR, "multiclass_model.joblib"))
    joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.joblib"))
    joblib.dump({"w_struct": W_STRUCT, "w_nlp": W_NLP}, os.path.join(MODELS_DIR, "ensemble_weights.joblib"))

    with open(os.path.join(REPORTS_DIR, "evaluation_report.json"), "w") as f:
        json.dump({
            "evaluation_notice": (
                "Hybrid evaluation: legitimate/spam samples are real Apache SpamAssassin emails; "
                "phishing, BEC and malware scenarios are synthetic. Do not claim production performance "
                "until evaluated on an independent real phishing-email corpus."
            ),
            "dataset_path": os.path.basename(dataset_path),
            "dataset_rows": int(len(df)),
            "label_distribution": {str(label): int(count) for label, count in y_multiclass.value_counts().items()},
            "source_distribution": ({str(label): int(count) for label, count in df["data_source"].value_counts().items()}
                                    if "data_source" in df.columns else {"source": "not supplied"}),
            "ensemble_weights": {"structured": W_STRUCT, "nlp": W_NLP},
            "binary_classification_report": report,
            "confusion_matrix": cm,
            "roc_auc": auc,
            "multiclass_report": mc_report,
        }, f, indent=2)

    print("=== Binary (malicious vs legitimate) ===")
    print(classification_report(y_test, ensemble_preds, target_names=["legitimate", "malicious"]))
    print("ROC-AUC:", round(auc, 4))
    print("Confusion matrix [[TN, FP], [FN, TP]]:", cm)
    print("\n=== Attack-type classifier (multiclass) ===")
    print(classification_report(y_mc_test_enc, mc_preds, target_names=le.classes_))
    print(f"\nTraining data: {dataset_path}")
    print(f"Models saved to {MODELS_DIR}")
    print(f"Full report saved to {REPORTS_DIR}/evaluation_report.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SentinelMail models on a labelled CSV dataset.")
    parser.add_argument("--dataset", help="Path to labelled CSV. Defaults to hybrid data when available.")
    args = parser.parse_args()
    main(args.dataset)
