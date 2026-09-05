"""Build a balanced hackathon training set from real and scenario-labelled data."""

from pathlib import Path

import pandas as pd


DATA_DIR = Path(__file__).resolve().parent
SYNTHETIC_PATH = DATA_DIR / "emails_dataset.csv"
REAL_PATH = DATA_DIR / "real_spamassassin.csv"
OUTPUT_PATH = DATA_DIR / "hybrid_emails_dataset.csv"


def main() -> None:
    if not REAL_PATH.exists():
        raise FileNotFoundError("Run `python data/download_real_corpus.py` first.")
    synthetic = pd.read_csv(SYNTHETIC_PATH)
    # Retain labelled scenarios that a ham/spam corpus cannot provide.
    attack_scenarios = synthetic[synthetic["label"].isin(["phishing", "bec", "malware"])].copy()
    attack_scenarios["data_source"] = "Synthetic attack scenario"
    real = pd.read_csv(REAL_PATH)
    combined = pd.concat([real, attack_scenarios], ignore_index=True, sort=False)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    combined.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved {len(combined)} rows to {OUTPUT_PATH}")
    print("Labels:\n" + combined["label"].value_counts().to_string())
    print("Sources:\n" + combined["data_source"].value_counts().to_string())


if __name__ == "__main__":
    main()
