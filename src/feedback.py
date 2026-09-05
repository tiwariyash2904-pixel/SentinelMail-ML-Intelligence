"""Verified-feedback queue for safe, auditable model improvement."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


ALLOWED_LABELS = {"legitimate", "phishing", "bec", "malware", "spam"}
FEEDBACK_PATH = Path(__file__).resolve().parent.parent / "data" / "verified_feedback.jsonl"


def record_feedback(email: dict, correct_label: str, analyst_id: str | None = None) -> dict:
    if correct_label not in ALLOWED_LABELS:
        raise ValueError(f"'correct_label' must be one of: {', '.join(sorted(ALLOWED_LABELS))}.")
    record = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "correct_label": correct_label,
        "analyst_id": analyst_id or "anonymous",
        "email": email,
    }
    with FEEDBACK_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    return {"status": "queued_for_verified_retraining", "correct_label": correct_label,
            "message": "Feedback was saved. Retrain only after analyst review to avoid data poisoning."}
