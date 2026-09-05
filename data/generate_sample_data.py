"""
generate_sample_data.py
------------------------
Generates a synthetic labeled email dataset that mimics the structure of
real phishing/BEC/spam/malware/legitimate emails: headers, SPF/DKIM/DMARC
results, a Received-chain (with IPs, for the geolocation module), body
text, URLs, and attachment metadata.

This exists so the whole pipeline runs end-to-end without needing internet
access to pull real corpora (Nazario, CEAS, SpamAssassin, etc.). To use a
real dataset instead: parse your .eml files into the same column schema
produced here (see the `COLUMNS` list at the bottom) and feed that
DataFrame into src/features.py directly -- nothing else needs to change.
"""

import random
import uuid
from pathlib import Path
import pandas as pd
import numpy as np

random.seed(42)
np.random.seed(42)

LEGIT_DOMAINS = ["acmecorp.com", "globex.com", "initech.com", "umbrella.org", "wonka.co"]
LOOKALIKE_MAP = {
    "acmecorp.com": ["acme-corp.com", "acmec0rp.com", "acmecorp-support.com"],
    "globex.com": ["globex-security.com", "gl0bex.com"],
    "initech.com": ["initech-verify.com", "initech.co"],
    "umbrella.org": ["umbrella-alerts.com", "umbrella.org.verify.com"],
    "wonka.co": ["wonka-payroll.com", "wonkaco.com"],
}
BRAND_NAMES = ["PayPal", "Microsoft 365", "DocuSign", "Bank of India", "HR Portal", "IT Helpdesk"]

URGENT_PHRASES = [
    "Act now to avoid suspension", "Verify your account immediately",
    "Your password will expire in 24 hours", "Urgent: invoice overdue",
    "Immediate action required", "Confirm your identity within 12 hours",
    "Final notice before account closure", "Click here to unlock your account",
]
CREDENTIAL_PHRASES = [
    "please enter your username and password", "confirm your login credentials",
    "verify your card details", "update your billing information",
    "reset your password using the link below",
]
LEGIT_PHRASES = [
    "Please find attached the quarterly report", "Let's schedule a meeting next week",
    "Thanks for your help on the project", "Here is the agenda for tomorrow",
    "Attached is the invoice for last month's services", "Reminder: standup at 10am",
]
BEC_PHRASES = [
    "I need you to process a wire transfer urgently, call me before the bank closes",
    "Please purchase gift cards for a client and send the codes to me directly",
    "I'm in a meeting, can you handle this payment request quietly and quickly",
]

# Rough IP ranges tagged with plausible countries for the geolocation module.
IP_POOL = [
    ("103.21.244.10", "India"), ("49.36.128.44", "India"),
    ("185.220.101.5", "Russia"), ("45.155.205.12", "Romania"),
    ("103.253.145.33", "Nigeria"), ("8.8.8.8", "USA"),
    ("172.217.14.206", "USA"), ("13.107.42.14", "USA"),
    ("41.203.72.5", "Nigeria"), ("196.216.2.24", "South Africa"),
]

COLUMNS = [
    "email_id", "from_addr", "reply_to_addr", "return_path_addr",
    "spf_pass", "dkim_pass", "dmarc_pass", "num_received_hops",
    "originating_ip", "sender_domain_age_days",
    "subject", "body",
    "urls", "has_shortened_url", "has_ip_literal_url", "num_urls",
    "has_attachment", "attachment_ext", "attachment_entropy",
    "label",
]


def make_legit_email():
    domain = random.choice(LEGIT_DOMAINS)
    user = random.choice(["alice", "bob", "priya", "raj", "sam"])
    from_addr = f"{user}@{domain}"
    ip, _ = random.choice(IP_POOL[:3])  # legit traffic mostly from "home" ranges
    body = random.choice(LEGIT_PHRASES)
    return dict(
        from_addr=from_addr, reply_to_addr=from_addr, return_path_addr=from_addr,
        spf_pass=1, dkim_pass=1, dmarc_pass=1,
        num_received_hops=random.randint(2, 4),
        originating_ip=ip, sender_domain_age_days=random.randint(1000, 6000),
        subject=random.choice(["Weekly update", "Meeting notes", "Invoice attached", "Quick question"]),
        body=body,
        urls=[], has_shortened_url=0, has_ip_literal_url=0, num_urls=0,
        has_attachment=random.choice([0, 0, 1]),
        attachment_ext=random.choice(["pdf", "docx", "none"]),
        attachment_entropy=round(random.uniform(3.5, 5.5), 2),
        label="legitimate",
    )


def make_phishing_email():
    real_domain = random.choice(LEGIT_DOMAINS)
    fake_domain = random.choice(LOOKALIKE_MAP[real_domain])
    from_addr = f"support@{fake_domain}"
    reply_to = f"reply@{fake_domain}"
    ip, _ = random.choice(IP_POOL[3:])
    brand = random.choice(BRAND_NAMES)
    body = f"{random.choice(URGENT_PHRASES)}. {random.choice(CREDENTIAL_PHRASES)} for your {brand} account."
    url_domain = fake_domain if random.random() > 0.3 else f"http://{ip}/login"
    return dict(
        from_addr=from_addr, reply_to_addr=reply_to, return_path_addr=f"bounce@{fake_domain}",
        spf_pass=random.choice([0, 0, 1]), dkim_pass=0, dmarc_pass=0,
        num_received_hops=random.randint(4, 9),
        originating_ip=ip, sender_domain_age_days=random.randint(1, 60),
        subject=random.choice(URGENT_PHRASES),
        body=body,
        urls=[url_domain], has_shortened_url=random.choice([0, 1]),
        has_ip_literal_url=1 if "http://" in str(url_domain) and any(c.isdigit() for c in url_domain.split("/")[2].split(".")[0]) else 0,
        num_urls=random.randint(1, 3),
        has_attachment=random.choice([0, 1]),
        attachment_ext=random.choice(["exe", "js", "html", "none"]),
        attachment_entropy=round(random.uniform(6.5, 8.0), 2),
        label="phishing",
    )


def make_bec_email():
    domain = random.choice(LEGIT_DOMAINS)
    lookalike = random.choice(LOOKALIKE_MAP[domain])
    exec_name = random.choice(["CEO", "CFO", "Director"])
    from_addr = f"{exec_name.lower()}@{lookalike}"
    ip, _ = random.choice(IP_POOL[3:])
    return dict(
        from_addr=from_addr, reply_to_addr=f"{exec_name.lower()}.office@{lookalike}",
        return_path_addr=f"bounce@{lookalike}",
        spf_pass=0, dkim_pass=0, dmarc_pass=0,
        num_received_hops=random.randint(3, 7),
        originating_ip=ip, sender_domain_age_days=random.randint(1, 30),
        subject=random.choice(["Urgent request", "Quick favor needed", "Confidential - action needed"]),
        body=random.choice(BEC_PHRASES),
        urls=[], has_shortened_url=0, has_ip_literal_url=0, num_urls=0,
        has_attachment=0, attachment_ext="none", attachment_entropy=0.0,
        label="bec",
    )


def make_malware_email():
    domain = random.choice(LOOKALIKE_MAP[random.choice(LEGIT_DOMAINS)])
    from_addr = f"billing@{domain}"
    ip, _ = random.choice(IP_POOL[3:])
    return dict(
        from_addr=from_addr, reply_to_addr=from_addr, return_path_addr=from_addr,
        spf_pass=0, dkim_pass=0, dmarc_pass=0,
        num_received_hops=random.randint(4, 8),
        originating_ip=ip, sender_domain_age_days=random.randint(1, 90),
        subject=random.choice(["Invoice attached", "Your delivery failed", "Document for review"]),
        body="Please review the attached document and enable macros to view content.",
        urls=[], has_shortened_url=0, has_ip_literal_url=0, num_urls=0,
        has_attachment=1, attachment_ext=random.choice(["exe", "js", "docm", "zip"]),
        attachment_entropy=round(random.uniform(7.0, 8.0), 2),
        label="malware",
    )


def make_spam_email():
    ip, _ = random.choice(IP_POOL)
    return dict(
        from_addr=f"deals@{uuid.uuid4().hex[:6]}promo.com",
        reply_to_addr="noreply@promo.com", return_path_addr="bounce@promo.com",
        spf_pass=random.choice([0, 1]), dkim_pass=random.choice([0, 1]), dmarc_pass=0,
        num_received_hops=random.randint(2, 5),
        originating_ip=ip, sender_domain_age_days=random.randint(30, 500),
        subject=random.choice(["50% off today only!!!", "You've won a prize!", "Buy now, limited stock"]),
        body="Huge discounts on your favorite products, click to claim your free gift now!!!",
        urls=["http://cheapdeals-promo.com"], has_shortened_url=1, has_ip_literal_url=0,
        num_urls=1, has_attachment=0, attachment_ext="none", attachment_entropy=0.0,
        label="spam",
    )


def generate(n_per_class=400):
    rows = []
    generators = [make_legit_email, make_phishing_email, make_bec_email,
                  make_malware_email, make_spam_email]
    for gen in generators:
        for _ in range(n_per_class):
            row = gen()
            row["email_id"] = str(uuid.uuid4())
            rows.append(row)
    df = pd.DataFrame(rows)[COLUMNS]
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


if __name__ == "__main__":
    df = generate(n_per_class=400)
    output_path = Path(__file__).resolve().parent / "emails_dataset.csv"
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} rows -> {output_path}")
    print(df["label"].value_counts())
