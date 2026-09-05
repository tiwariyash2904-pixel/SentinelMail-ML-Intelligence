"""Parse RFC 5322 .eml files into the model's stable input contract."""

from __future__ import annotations

import base64
import hashlib
import math
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html import unescape


URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SHORTENER_RE = re.compile(r"(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)/", re.I)
IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)", re.I)


def _clean_html(value: str) -> str:
    return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", value))).strip()


def _body_text(message) -> str:
    parts = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        try:
            text = part.get_content()
        except (LookupError, UnicodeDecodeError):
            text = part.get_payload(decode=True) or b""
            text = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
        parts.append(_clean_html(text) if part.get_content_type() == "text/html" else str(text))
    return "\n".join(parts).strip()


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = [payload.count(bytes([byte])) for byte in range(256)]
    return round(-sum((count / len(payload)) * math.log2(count / len(payload)) for count in counts if count), 3)


def _auth_passes(header: str, mechanism: str) -> int:
    return int(bool(re.search(rf"\b{re.escape(mechanism)}=(?:pass|bestguesspass)\b", header, re.I)))


def _originating_ip(received_headers: list[str]) -> str | None:
    # Earliest (last) Received header is closest to the source; private IPs are
    # retained because the geolocation layer will describe them as non-routable.
    for header in reversed(received_headers):
        matches = IP_RE.findall(header)
        if matches:
            return matches[0]
    return None


def parse_eml(raw_email: bytes) -> dict:
    """Extract headers, content, URLs and attachment metadata from an .eml."""
    if not raw_email:
        raise ValueError("The uploaded .eml file is empty.")
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    from_name, from_addr = parseaddr(message.get("From", ""))
    _, reply_to_addr = parseaddr(message.get("Reply-To", ""))
    _, return_path_addr = parseaddr(message.get("Return-Path", ""))
    received = message.get_all("Received", [])
    auth = " ".join(message.get_all("Authentication-Results", []))
    subject = str(message.get("Subject", ""))
    body = _body_text(message)
    urls = [match.rstrip(".,;:!?)]") for match in URL_RE.findall(f"{subject}\n{body}")]

    attachments = []
    max_entropy = 0.0
    for part in message.walk():
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        entropy = _entropy(payload)
        max_entropy = max(max_entropy, entropy)
        digest = hashlib.sha256(payload).hexdigest() if payload else None
        attachments.append({
            "filename": filename or "unnamed_attachment",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": digest,
            "entropy": entropy,
        })

    ext = "none"
    if attachments and "." in attachments[0]["filename"]:
        ext = attachments[0]["filename"].rsplit(".", 1)[1].lower()
    # Domain age cannot be truthfully inferred from an email alone. It is left
    # unavailable until a WHOIS/domain-intelligence service enriches the record.
    return {
        "from_addr": from_addr,
        "from_display_name": from_name,
        "reply_to_addr": reply_to_addr or from_addr,
        "return_path_addr": return_path_addr or from_addr,
        "spf_pass": _auth_passes(auth, "spf"),
        "dkim_pass": _auth_passes(auth, "dkim"),
        "dmarc_pass": _auth_passes(auth, "dmarc"),
        "num_received_hops": len(received),
        "originating_ip": _originating_ip(received),
        "sender_domain_age_days": None,
        "domain_age_status": "unavailable",
        "subject": subject,
        "body": body,
        "urls": urls,
        "has_shortened_url": int(any(SHORTENER_RE.search(url) for url in urls)),
        "has_ip_literal_url": int(any(IP_URL_RE.search(url) for url in urls)),
        "num_urls": len(urls),
        "has_attachment": int(bool(attachments)),
        "attachment_ext": ext,
        "attachment_entropy": max_entropy,
        "attachments": attachments,
        "message_id": message.get("Message-ID"),
        "date": str(message.get("Date", "")),
    }
