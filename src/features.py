"""
features.py
------------
Turns a raw email record (dict or DataFrame row) into the structured
feature vector used by the baseline model, plus the raw text used by the
NLP model. Keep this the single source of truth for feature definitions --
both training and the live API import from here so train/serve skew can't
creep in.
"""

import ast
import re
import difflib
from urllib.parse import urlparse
import pandas as pd
import numpy as np

URGENT_WORDS = [
    "urgent", "immediately", "act now", "verify", "suspend", "final notice",
    "confirm your", "24 hours", "click here", "unlock", "expire",
]
CREDENTIAL_WORDS = [
    "password", "username", "login", "credentials", "card details",
    "billing information", "ssn", "social security",
]
KNOWN_BRANDS_DOMAINS = [
    "paypal.com", "microsoft.com", "docusign.com", "google.com", "apple.com",
]

STRUCTURED_FEATURE_NAMES = [
    "spf_pass", "dkim_pass", "dmarc_pass",
    "reply_to_mismatch", "num_received_hops", "sender_domain_age_days",
    "num_urls", "has_shortened_url", "has_ip_literal_url",
    "max_brand_domain_similarity",
    "has_attachment", "attachment_is_risky_ext", "attachment_entropy",
    "urgent_word_count", "credential_word_count",
    "exclamation_count", "all_caps_word_ratio",
]

RISKY_EXTENSIONS = {"exe", "js", "vbs", "scr", "docm", "xlsm", "zip", "html"}


def _domain_of(addr: str) -> str:
    if not isinstance(addr, str) or "@" not in addr:
        return ""
    return addr.split("@")[-1].lower().strip()


def _as_url_list(value) -> list[str]:
    """Normalise URLs received from JSON, CSV, or the email parser safely."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item]
    if not isinstance(value, str) or not value.strip():
        return []
    value = value.strip()
    if value.startswith("["):
        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, (list, tuple)):
                return [str(item) for item in parsed if item]
        except (ValueError, SyntaxError):
            return []
    return [value]


def _url_host(url: str) -> str:
    """Return a URL host even if a dataset omitted its scheme."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower().strip(".")


def _as_int(value, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _reply_to_mismatch(row) -> int:
    return int(_domain_of(row.get("from_addr", "")) != _domain_of(row.get("reply_to_addr", "")))


def _max_brand_similarity(row) -> float:
    """How close is the sender/URL domain to a known, high-value brand domain?
    High similarity + not an exact match is the classic typosquat signature."""
    candidates = [_domain_of(row.get("from_addr", ""))]
    for u in _as_url_list(row.get("urls", [])):
        host = _url_host(u)
        if host:
            candidates.append(host)

    best = 0.0
    for cand in candidates:
        if not cand:
            continue
        for brand in KNOWN_BRANDS_DOMAINS:
            if cand == brand:
                continue  # exact match to a real brand domain isn't a spoof signal
            ratio = difflib.SequenceMatcher(None, cand, brand).ratio()
            best = max(best, ratio)
    return round(best, 3)


def _text_signals(subject: str, body: str) -> dict:
    subject = subject if isinstance(subject, str) else ""
    body = body if isinstance(body, str) else ""
    text = f"{subject or ''} {body or ''}".lower()
    urgent_count = sum(text.count(w) for w in URGENT_WORDS)
    cred_count = sum(text.count(w) for w in CREDENTIAL_WORDS)
    exclam = (subject or "").count("!") + (body or "").count("!")
    words = re.findall(r"[A-Za-z]{3,}", f"{subject or ''} {body or ''}")
    caps_ratio = (sum(1 for w in words if w.isupper()) / len(words)) if words else 0.0
    return dict(
        urgent_word_count=urgent_count,
        credential_word_count=cred_count,
        exclamation_count=exclam,
        all_caps_word_ratio=round(caps_ratio, 3),
    )


def extract_structured_features(row: dict) -> dict:
    """row: a dict with the raw email fields (see data/generate_sample_data.COLUMNS)."""
    urls = _as_url_list(row.get("urls", []))
    ext = str(row.get("attachment_ext", "none")).lower()

    feats = {
        "spf_pass": _as_int(row.get("spf_pass", 0)),
        "dkim_pass": _as_int(row.get("dkim_pass", 0)),
        "dmarc_pass": _as_int(row.get("dmarc_pass", 0)),
        "reply_to_mismatch": _reply_to_mismatch(row),
        "num_received_hops": _as_int(row.get("num_received_hops", 0)),
        "sender_domain_age_days": _as_int(row.get("sender_domain_age_days", 365)),
        "num_urls": _as_int(row.get("num_urls", len(urls))),
        "has_shortened_url": _as_int(row.get("has_shortened_url", 0)),
        "has_ip_literal_url": _as_int(row.get("has_ip_literal_url", 0)),
        "max_brand_domain_similarity": _max_brand_similarity(row),
        "has_attachment": _as_int(row.get("has_attachment", 0)),
        "attachment_is_risky_ext": int(ext in RISKY_EXTENSIONS),
        "attachment_entropy": _as_float(row.get("attachment_entropy", 0.0)),
    }
    feats.update(_text_signals(row.get("subject", ""), row.get("body", "")))
    return feats


def build_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    rows = df.to_dict(orient="records")
    feats = [extract_structured_features(r) for r in rows]
    fdf = pd.DataFrame(feats)[STRUCTURED_FEATURE_NAMES]
    return fdf


def get_text_series(df: pd.DataFrame) -> pd.Series:
    return df["subject"].fillna("").astype(str) + " " + df["body"].fillna("").astype(str)
