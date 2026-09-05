"""Download and parse a small, labelled real-email baseline corpus.

Source: Apache SpamAssassin Public Corpus. The corpus distinguishes ham from
spam; it does not label phishing, BEC, or malware. It is therefore combined
with the controlled multi-attack demo scenarios by ``build_hybrid_dataset``.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
from pathlib import Path
from urllib.request import urlopen

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from email_parser import parse_eml  # noqa: E402

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus/"
CORPORA = {
    "20030228_easy_ham.tar.bz2": "legitimate",
    "20030228_spam.tar.bz2": "spam",
}
MAX_PER_CLASS = 800


def records_from_archive(url: str, label: str) -> list[dict]:
    with urlopen(url, timeout=60) as response:
        archive_bytes = response.read()
    records = []
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:bz2") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                continue
            raw = stream.read()
            try:
                record = parse_eml(raw)
            except ValueError:
                continue
            record["email_id"] = hashlib.sha256(raw).hexdigest()
            record["label"] = label
            record["data_source"] = "Apache SpamAssassin Public Corpus"
            records.append(record)
    return records


def main() -> None:
    collected = []
    for filename, label in CORPORA.items():
        print(f"Downloading {filename} ...")
        collected.extend(records_from_archive(BASE_URL + filename, label))
    df = pd.DataFrame(collected)
    balanced = []
    for label, group in df.groupby("label"):
        balanced.append(group.sample(n=min(MAX_PER_CLASS, len(group)), random_state=42))
    output = pd.concat(balanced, ignore_index=True).sample(frac=1, random_state=42)
    output_path = Path(__file__).resolve().parent / "real_spamassassin.csv"
    output.to_csv(output_path, index=False)
    print(f"Saved {len(output)} real labelled emails to {output_path}")
    print(output["label"].value_counts().to_string())


if __name__ == "__main__":
    main()
