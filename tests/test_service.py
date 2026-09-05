import io
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from api import app
from features import extract_structured_features


MALICIOUS = {
    "from_addr": "support@acme-corp.com", "reply_to_addr": "reply@acme-corp.com",
    "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0, "num_received_hops": 7,
    "originating_ip": "185.220.101.5", "sender_domain_age_days": 12,
    "subject": "Urgent: Verify your account immediately",
    "body": "Your password will expire in 24 hours. Please enter your username and password.",
    "urls": ["http://acme-corp.com/login"], "has_shortened_url": 1, "num_urls": 2,
    "has_attachment": 1, "attachment_ext": "exe", "attachment_entropy": 7.8,
}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        app.config["GEOLOOKUP_ENABLED"] = False
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_malicious_email_returns_evidence(self):
        response = self.client.post("/predict", json=MALICIOUS)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["is_malicious"])
        self.assertGreater(response.json["risk_score"], 0.5)
        self.assertTrue(response.json["explanation"])

    def test_malformed_json_contract_is_rejected(self):
        response = self.client.post("/predict", json={"from_addr": 99, "subject": "x", "body": "x"})
        self.assertEqual(response.status_code, 400)

    def test_url_csv_value_is_parsed_safely(self):
        features = extract_structured_features({**MALICIOUS, "urls": "['https://microsoft-login.example']"})
        self.assertGreater(features["max_brand_domain_similarity"], 0)

    def test_eml_endpoint_extracts_forensic_artifacts(self):
        raw = b"From: help@acme-corp.com\nTo: user@example.com\nSubject: Verify account\nAuthentication-Results: mx; spf=fail dkim=fail dmarc=fail\nReceived: from 185.220.101.5 by mx.example\nContent-Type: text/plain\n\nVisit http://185.220.101.5/login and enter your password."
        response = self.client.post("/analyze-eml", data={"file": (io.BytesIO(raw), "sample.eml")})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["parsed_email"]["originating_ip"], "185.220.101.5")
        self.assertEqual(response.json["parsed_email"]["has_ip_literal_url"], 1)
        self.assertEqual(response.json["analysis"]["domain_age"]["status"], "unavailable")

    def test_verified_feedback_is_queued_not_applied_automatically(self):
        with TemporaryDirectory() as temp_dir:
            feedback_path = Path(temp_dir) / "feedback.jsonl"
            with patch("feedback.FEEDBACK_PATH", feedback_path):
                response = self.client.post("/feedback", json={"email": MALICIOUS, "correct_label": "phishing"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["status"], "queued_for_verified_retraining")
            self.assertTrue(feedback_path.exists())


if __name__ == "__main__":
    unittest.main()
