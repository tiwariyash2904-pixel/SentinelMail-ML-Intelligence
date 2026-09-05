"""Flask service for threat scoring raw email records and uploaded .eml files."""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory

from email_parser import parse_eml
from explain import explain_prediction
from feedback import record_feedback
from features import STRUCTURED_FEATURE_NAMES, extract_structured_features
from intelligence import behavioural_anomaly, ip_intelligence, url_intelligence, correlate_iocs, hash_intelligence, domain_intelligence

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MODEL_VERSION = "1.0.0"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["GEOLOOKUP_ENABLED"] = os.getenv("GEOLOOKUP_ENABLED", "true").lower() not in {"0", "false", "no"}

struct_model = joblib.load(MODELS_DIR / "struct_model.joblib")
vectorizer = joblib.load(MODELS_DIR / "tfidf_vectorizer.joblib")
nlp_model = joblib.load(MODELS_DIR / "nlp_model.joblib")
multiclass_model = joblib.load(MODELS_DIR / "multiclass_model.joblib")
label_encoder = joblib.load(MODELS_DIR / "label_encoder.joblib")
weights = joblib.load(MODELS_DIR / "ensemble_weights.joblib")


def _risk_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def _recommended_action(score: float) -> str:
    if score >= 0.85:
        return "Quarantine the message, block associated URLs/attachments, and alert security operations."
    if score >= 0.65:
        return "Hold for analyst review; do not open links or attachments until cleared."
    if score >= 0.35:
        return "Deliver with a caution banner and monitor for follow-up activity."
    return "No automated containment recommended; retain telemetry for monitoring."


def _validate_email(email: dict) -> None:
    if not isinstance(email, dict):
        raise ValueError("Request JSON must be an object.")
    for field in ("from_addr", "subject", "body"):
        if not isinstance(email.get(field, ""), str):
            raise ValueError(f"'{field}' must be a string.")
    if "urls" in email and not isinstance(email["urls"], (str, list, tuple)):
        raise ValueError("'urls' must be a string or a list of strings.")
    if "geo_context" in email and not isinstance(email["geo_context"], dict):
        raise ValueError("'geo_context' must be an object when supplied.")
    if "sender_history" in email and not isinstance(email["sender_history"], list):
        raise ValueError("'sender_history' must be a list when supplied.")


def _domain_age(email: dict) -> dict:
    """Keep absence of WHOIS enrichment visible without breaking model inputs."""
    value = email.get("sender_domain_age_days")
    try:
        days = int(float(value))
        if days < 0:
            raise ValueError
        return {"days": days, "status": "available"}
    except (TypeError, ValueError):
        return {"days": None, "status": "unavailable"}


def predict_email(email: dict) -> dict:
    """Return the stable, integration-friendly threat-analysis response."""
    _validate_email(email)
    struct_feats = extract_structured_features(email)
    struct_df = pd.DataFrame([struct_feats])[STRUCTURED_FEATURE_NAMES]
    text = f"{email.get('subject', '')} {email.get('body', '')}"

    struct_prob = float(struct_model.predict_proba(struct_df)[0, 1])
    nlp_prob = float(nlp_model.predict_proba(vectorizer.transform([text]))[0, 1])
    base_risk = weights["w_struct"] * struct_prob + weights["w_nlp"] * nlp_prob
    geo = ip_intelligence(
        email.get("originating_ip"), email.get("geo_context"),
        lookup_online=app.config["GEOLOOKUP_ENABLED"],
    )
    anomaly = behavioural_anomaly(email, email.get("sender_history"))

    raw_urls = email.get("urls", [])
    if isinstance(raw_urls, str):
        raw_urls = [raw_urls]
    url_intel = [url_intelligence(u) for u in raw_urls]
    ioc_correlation = correlate_iocs(email, url_intel)

    attachments = email.get("attachments", [])
    hash_intel = [
        hash_intelligence(att.get("sha256"), att.get("filename"))
        for att in attachments if isinstance(att, dict)
    ]

    sender_domain = str(email.get("from_addr", "")).split("@")[-1].lower()
    domain_intel = domain_intelligence(sender_domain) if sender_domain else None

    risk_score = min(1.0, base_risk + (0.15 * anomaly["score"]) + (0.12 if geo["risk_indicators"] and geo["is_public"] else 0.0))
    is_malicious = bool(risk_score >= 0.5)

    mc_probs = multiclass_model.predict_proba(struct_df)[0]
    mc_idx = int(mc_probs.argmax())
    predicted_type = label_encoder.inverse_transform([mc_idx])[0]
    attack_type = predicted_type if is_malicious else "legitimate"
    explanation = explain_prediction(struct_model, struct_df.iloc[0]) if is_malicious else []
    for signal in anomaly["signals"]:
        explanation.append({"feature": "behavioural_anomaly", "reason": signal,
                            "value": anomaly["score"], "contribution_score": round(anomaly["score"] * 0.15, 4)})
    for signal in geo["risk_indicators"]:
        if "high-risk" in signal.lower() or "flagged" in signal.lower():
            explanation.append({"feature": "geolocation_intelligence", "reason": signal,
                                "value": geo.get("country_code") or geo.get("ip"), "contribution_score": 0.12})

    return {
        "model_version": MODEL_VERSION,
        "is_malicious": is_malicious,
        "risk_score": round(float(risk_score), 4),
        "base_ml_risk_score": round(float(base_risk), 4),
        "risk_level": _risk_level(risk_score),
        "attack_type": attack_type,
        "attack_type_confidence": round(float(mc_probs[mc_idx]), 4),
        "recommended_action": _recommended_action(risk_score),
        "explanation": explanation[:6],
        "originating_ip": email.get("originating_ip"),
        "ip_intelligence": geo,
        "url_intelligence": url_intel,
        "ioc_correlation": ioc_correlation,
        "hash_intelligence": hash_intel,
        "domain_intelligence": domain_intel,
        "behavioural_anomaly": anomaly,
        "domain_age": _domain_age(email),
        "forensic_artifacts": {"urls": email.get("urls", []), "attachments": email.get("attachments", []),
                               "message_id": email.get("message_id")},
    }


@app.errorhandler(413)
def upload_too_large(_error):
    return jsonify({"error": f"File is too large. Maximum is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."}), 413


@app.route("/", methods=["GET"])
def dashboard():
    return send_from_directory(BASE_DIR / "src" / "static", "index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_version": MODEL_VERSION})


@app.route("/predict", methods=["POST"])
def predict():
    email = request.get_json(silent=True)
    if email is None:
        return jsonify({"error": "Send a JSON request body with Content-Type: application/json."}), 400
    try:
        return jsonify(predict_email(email))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/analyze-eml", methods=["POST"])
def analyze_eml():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Upload an .eml file as multipart form field 'file'."}), 400
    if not uploaded.filename.lower().endswith(".eml"):
        return jsonify({"error": "Only .eml files are accepted."}), 400
    try:
        email = parse_eml(uploaded.read())
        return jsonify({"parsed_email": email, "analysis": predict_email(email)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/feedback", methods=["POST"])
def feedback():
    """Queue analyst-verified labels for audited future retraining."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("email"), dict):
        return jsonify({"error": "Send JSON with an 'email' object and 'correct_label'."}), 400
    try:
        _validate_email(payload["email"])
        return jsonify(record_feedback(payload["email"], payload.get("correct_label"), payload.get("analyst_id")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)