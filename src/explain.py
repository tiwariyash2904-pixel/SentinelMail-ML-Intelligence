"""
explain.py
----------
Produces a human-readable "why was this flagged" explanation for a single
prediction. This is what the forensic-intelligence module consumes to
write its evidence report -- so keep the output plain-language, not raw
feature names.

No SHAP available in this environment (no internet to install it), so this
uses a transparent, easy-to-defend-in-a-demo alternative: global feature
importances from the trained model, scaled by how unusual each feature
value is for this specific email. Swap in `shap.TreeExplainer` later for
per-instance additive attributions -- struct_model is already a
GradientBoostingClassifier, so it's SHAP-compatible out of the box.
"""

import numpy as np
import pandas as pd

FEATURE_LABELS = {
    "spf_pass": "SPF check failed",
    "dkim_pass": "DKIM signature failed",
    "dmarc_pass": "DMARC check failed",
    "reply_to_mismatch": "Reply-To address doesn't match the sending domain",
    "num_received_hops": "unusually long routing (Received) chain",
    "sender_domain_age_days": "sending domain was registered very recently",
    "num_urls": "contains multiple links",
    "has_shortened_url": "uses a shortened/obfuscated URL",
    "has_ip_literal_url": "link points to a raw IP address instead of a domain",
    "max_brand_domain_similarity": "sender or link domain closely mimics a known brand (typosquat)",
    "has_attachment": "contains an attachment",
    "attachment_is_risky_ext": "attachment has a high-risk file type",
    "attachment_entropy": "attachment content looks packed/obfuscated",
    "urgent_word_count": "body uses urgency/pressure language",
    "credential_word_count": "body requests credentials or sensitive account details",
    "exclamation_count": "excessive punctuation/exclamation marks",
    "all_caps_word_ratio": "high proportion of ALL-CAPS words",
}

# Feature direction: 1 means "higher value = more suspicious"
SUSPICIOUS_WHEN_HIGH = {
    "spf_pass": False, "dkim_pass": False, "dmarc_pass": False,
    "reply_to_mismatch": True, "num_received_hops": True,
    "sender_domain_age_days": False,  # inverted below (young domain = suspicious)
    "num_urls": True, "has_shortened_url": True, "has_ip_literal_url": True,
    "max_brand_domain_similarity": True, "has_attachment": True,
    "attachment_is_risky_ext": True, "attachment_entropy": True,
    "urgent_word_count": True, "credential_word_count": True,
    "exclamation_count": True, "all_caps_word_ratio": True,
}


def explain_prediction(struct_model, feature_row: pd.Series, top_k: int = 4) -> list:
    """Returns the top_k plain-language reasons behind a flagged email,
    ranked by (global feature importance x local suspiciousness)."""
    importances = struct_model.feature_importances_
    names = feature_row.index.tolist()
    values = feature_row.values

    scores = []
    for name, val, imp in zip(names, values, importances):
        suspicious_high = SUSPICIOUS_WHEN_HIGH.get(name, True)
        if name in ("spf_pass", "dkim_pass", "dmarc_pass"):
            local_signal = 1.0 if val == 0 else 0.0
        elif name == "sender_domain_age_days":
            local_signal = 1.0 if val < 90 else 0.0
        elif name in ("has_attachment", "has_shortened_url", "has_ip_literal_url",
                      "attachment_is_risky_ext", "reply_to_mismatch"):
            local_signal = float(val)
        else:
            # normalize continuous-ish counts into a rough 0-1 "how unusual" signal
            local_signal = min(float(val) / 5.0, 1.0) if suspicious_high else 0.0

        scores.append((name, imp * local_signal, val))

    scores.sort(key=lambda x: x[1], reverse=True)
    reasons = []
    for name, score, val in scores[:top_k]:
        if score <= 0:
            continue
        reasons.append({
            "feature": name,
            "reason": FEATURE_LABELS.get(name, name),
            "value": val if not isinstance(val, np.generic) else val.item(),
            "contribution_score": round(float(score), 4),
        })
    return reasons
