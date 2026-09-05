# SentinelMail — AI-Powered Email Threat Detection & Forensic Intelligence

**SIN26206 hackathon submission · AI/ML threat-detection module**

SentinelMail turns an email record or a real `.eml` file into an explainable security decision. It combines structured header/URL/attachment signals, NLP content scoring, attack-type classification, forensic artifact extraction, IP/geolocation context, and sender-behaviour anomaly signals.

## What the project demonstrates

| Capability | What it does |
|---|---|
| Threat classification | Labels email as legitimate or malicious and estimates risk from 0 to 1. |
| Attack type | Distinguishes phishing, BEC, malware and spam. |
| Explainable AI | Returns the concrete evidence that caused a flag, in plain language. |
| `.eml` forensics | Extracts headers, SPF/DKIM/DMARC results, received-chain IP, URLs, attachment hashes, file types and entropy. |
| Live geolocation | Resolves public IP addresses into country/city/region/ASN data, with a safe unavailable state if offline. |
| Behavioural intelligence | Flags new senders, unfamiliar Reply-To domains and country baseline deviations. |
| Feedback-guided improvement | Queues verified analyst labels for audited future retraining; it never retrains silently on untrusted input. |
| Demo console | Provides a browser UI at `/` plus documented JSON and file-upload APIs. |

## Architecture

```text
Raw email JSON / .eml upload
            │
            ├── Email parser ──► headers, URLs, attachments, SHA-256, source IP
            ├── Feature engineering ──► authentication, URL, domain, attachment, text signals
            ├── Structured ML model (Gradient Boosting) ──┐
            ├── NLP model (TF-IDF + Logistic Regression) ─┼──► weighted threat risk
            └── Attack-type classifier ───────────────────┘
                          │
             Geo + behavioural intelligence
                          │
          Explainable evidence + recommended response
```

## Quick start

```bash
python -m pip install -r requirements.txt
python data/generate_sample_data.py
python src/train.py
python src/api.py
```

Open [http://localhost:8000](http://localhost:8000) to use the demo console. Run verification tests with:

```bash
python -m unittest discover -s tests -v
```

## API

### `POST /predict` — analyse structured email telemetry

```json
{
  "from_addr": "support@acme-corp.com",
  "reply_to_addr": "reply@acme-corp.com",
  "spf_pass": 0, "dkim_pass": 0, "dmarc_pass": 0,
  "num_received_hops": 7, "originating_ip": "185.220.101.5",
  "sender_domain_age_days": 12,
  "subject": "Urgent: Verify your account immediately",
  "body": "Your password will expire in 24 hours. Enter your username and password.",
  "urls": ["http://acme-corp.com/login"],
  "has_shortened_url": 1, "num_urls": 1,
  "has_attachment": 1, "attachment_ext": "exe", "attachment_entropy": 7.8,
  "geo_context": {"country_code": "RU", "city": "Moscow", "asn": "AS12345", "is_known_malicious": true},
  "sender_history": [{"from_addr": "support@acme-corp.com", "country_code": "IN", "reply_to_domain": "acme-corp.com", "hour_utc": 9}]
}
```

`geo_context` and `sender_history` are optional. Public IPs are automatically resolved through ipwho.is when internet is available; `geo_context` can override this with your team's own provider. Set `GEOLOOKUP_ENABLED=false` to disable outbound IP lookup. `sender_history` is the contract for a historical telemetry store.

The response includes `risk_score`, `base_ml_risk_score`, `risk_level`, `attack_type`, `explanation`, `recommended_action`, `ip_intelligence`, `behavioural_anomaly`, and `forensic_artifacts`.

### `POST /analyze-eml` — parse and analyse a real email

```bash
curl -X POST http://localhost:8000/analyze-eml -F "file=@data/sample_phishing.eml"
```

### `GET /health`

Returns service status and the model version. Invalid input receives a clear `400` response; uploads are limited to 5 MB.

### `POST /feedback` — analyst-verified improvement queue

```json
{
  "email": {"from_addr": "sender@example.com", "subject": "...", "body": "..."},
  "correct_label": "phishing",
  "analyst_id": "security-analyst-1"
}
```

The correction is stored in `data/verified_feedback.jsonl` for review and scheduled retraining. This makes the improvement process safe and auditable; an attacker cannot poison the model merely by submitting feedback.

## Project layout

```text
data/                  sample data generator and an uploadable .eml demo
models/                trained, compatible model artifacts
reports/               evaluation report generated at training time
src/
  api.py               Flask API and demo entry point
  email_parser.py      safe RFC 5322 .eml parser and forensic extraction
  features.py          shared feature engineering (train/serve parity)
  intelligence.py      geo-context and behavioural anomaly intelligence
  explain.py           plain-language evidence generation
  train.py             model training and evaluation
  static/index.html    browser dashboard
tests/test_service.py  API, parser and safety verification
```

## Model design

1. A **Gradient Boosting** model evaluates mail authentication, Reply-To mismatch, sender-domain age, URL obfuscation, typosquatting similarity, attachment risk, and text-signal features.
2. A **TF-IDF + Logistic Regression** model evaluates subject/body language such as urgency and credential requests.
3. A second Gradient Boosting classifier predicts the **attack type**.
4. The structured and NLP probabilities are combined at **60% / 40%**. Behaviour and geo intelligence make only a bounded adjustment, so weak historical signals cannot override core ML evidence.

## Evaluation data and honest results

The submitted model trains and evaluates on a **hybrid 2,501-email dataset**:

- **1,301 real labelled ham/spam messages** from the Apache SpamAssassin Public Corpus.
- **1,200 controlled synthetic scenarios** for phishing, BEC and malware, which the public ham/spam corpus does not label.

The current held-out binary result is **0.96 accuracy** and **0.9955 ROC-AUC**. This is a meaningful improvement over synthetic-only validation, but it is still not a production-performance claim: only the legitimate/spam portion has real-email labels. The machine-readable report states this scope precisely in `reports/evaluation_report.json`.

For production-quality phishing evaluation, add authorised real phishing/BEC/malware `.eml` samples to the same schema, retrain, and report precision/recall, PR-AUC, false-positive rate and results on an entirely held-out campaign/time period. Do not upload real private email to public services without permission.

## Hackathon demo flow

1. Open the dashboard and run the preloaded phishing example.
2. Point out the risk level, attack type, ML explanation, IP intelligence and recommended action.
3. Upload `data/sample_phishing.eml` to demonstrate real email parsing and artifact extraction.
4. Explain the team integration: the geo module enriches `geo_context`; the forensic module consumes `forensic_artifacts` and `explanation`.
5. State the evaluation limitation honestly, then show the real-world upgrade path.

## Security boundaries

- URL-list parsing uses `ast.literal_eval`, never `eval`.
- Attachments are inspected for metadata and SHA-256 only; they are never executed.
- Offline mode does not fabricate geographic facts. It accepts verified enrichment through `geo_context`.
- Domain age is returned as **unavailable** unless a WHOIS/domain-intelligence integration supplies a real value; it is never invented from the email itself.
- This is decision support for a hackathon prototype, not an autonomous mail-blocking system.
