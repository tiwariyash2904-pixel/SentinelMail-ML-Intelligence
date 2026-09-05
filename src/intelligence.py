"""Offline-safe geographic and behavioural intelligence enrichment."""

from __future__ import annotations

import difflib
import ipaddress
import json
import os
from datetime import datetime, timezone
from functools import lru_cache
from urllib.request import Request, urlopen
from urllib.parse import urlparse


HIGH_RISK_COUNTRIES = {"RU", "NG", "KP", "IR"}
KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "loan", "gq", "tk", "ml", "cf", "ga",
}

KNOWN_BRAND_DOMAINS = {
    "paypal.com", "microsoft.com", "docusign.com", "google.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "bankofamerica.com",
}


@lru_cache(maxsize=1024)
def _lookup_ipwhois(ip_value: str) -> dict:
    """Look up public IP location through ipwho.is with a short safe timeout."""
    request = Request(
        f"https://ipwho.is/{ip_value}",
        headers={"User-Agent": "SentinelMail-Hackathon/1.0"},
    )
    try:
        with urlopen(request, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {"lookup_status": "unavailable", "lookup_provider": "ipwho.is"}
    if payload.get("success") is False:
        return {"lookup_status": "unavailable", "lookup_provider": "ipwho.is"}
    connection = payload.get("connection") or {}
    return {
        "lookup_status": "resolved",
        "lookup_provider": "ipwho.is",
        "country_code": payload.get("country_code"),
        "city": payload.get("city"),
        "region": payload.get("region"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "timezone": (payload.get("timezone") or {}).get("id"),
        "asn": connection.get("asn"),
        "organization": connection.get("org"),
    }


def ip_intelligence(ip_value: str | None, supplied_geo: dict | None = None, lookup_online: bool = True) -> dict:
    """Describe IP safety and, when permitted, resolve its public location.

    A geo service can provide ``country_code``, ``city``, ``asn`` and
    ``is_known_malicious`` in supplied_geo. This makes integration explicit.
    """
    result = {"ip": ip_value, "classification": "unknown", "is_public": False,
              "country_code": None, "city": None, "asn": None, "region": None,
              "latitude": None, "longitude": None, "timezone": None, "organization": None,
              "lookup_status": "not_attempted", "lookup_provider": None,
              "risk_indicators": []}
    if supplied_geo:
        result.update({key: supplied_geo.get(key) for key in ("country_code", "city", "asn") if supplied_geo.get(key)})
        if supplied_geo.get("is_known_malicious"):
            result["risk_indicators"].append("IP was flagged by the connected threat-intelligence source")
    if not ip_value:
        result["risk_indicators"].append("No originating IP was found in the message headers")
        return result
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        result["classification"] = "invalid"
        result["risk_indicators"].append("Originating IP is invalid")
        return result
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        result["classification"] = "non_routable"
        result["risk_indicators"].append("Originating IP is private/reserved and cannot be geolocated")
    else:
        result["classification"] = "public"
        result["is_public"] = True
        if lookup_online and not supplied_geo:
            result.update(_lookup_ipwhois(str(ip)))
        elif supplied_geo:
            result["lookup_status"] = "provided_by_integration"
            result["lookup_provider"] = "geo_context"
    if result["country_code"] and result["country_code"].upper() in HIGH_RISK_COUNTRIES:
        result["risk_indicators"].append("Source country is in the configured high-risk watch list")
    return result


def url_intelligence(url_value: str | None) -> dict:
    """Describe basic risk characteristics of a single URL, offline-safe.

    No external lookups here -- purely structural signals that are strong,
    fast, and don't depend on any API being available.
    """
    result = {
        "url": url_value,
        "https": None,
        "ip_based": False,
        "shortened": False,
        "suspicious_tld": False,
        "reputation": "unknown",
        "risk_indicators": [],
    }

    if not url_value:
        result["risk_indicators"].append("No URL supplied")
        return result

    try:
        parsed = urlparse(url_value)
    except Exception:
        result["reputation"] = "invalid"
        result["risk_indicators"].append("URL could not be parsed")
        return result

    host = (parsed.hostname or "").lower()

    result["https"] = parsed.scheme == "https"
    if not result["https"]:
        result["risk_indicators"].append("URL does not use HTTPS")

    try:
        ipaddress.ip_address(host)
        result["ip_based"] = True
        result["risk_indicators"].append("URL uses a raw IP address instead of a domain name")
    except ValueError:
        pass

    if host in KNOWN_URL_SHORTENERS:
        result["shortened"] = True
        result["risk_indicators"].append("URL uses a known link-shortening service")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        result["suspicious_tld"] = True
        result["risk_indicators"].append(f"URL uses a TLD commonly abused for phishing (.{tld})")

    flag_count = len(result["risk_indicators"])
    if flag_count == 0:
        result["reputation"] = "clean"
    elif flag_count == 1:
        result["reputation"] = "suspicious"
    else:
        result["reputation"] = "malicious"

    return result


def correlate_iocs(email: dict, url_intel: list[dict] | None = None) -> dict:
    """Link extracted indicators (IP, domain, URLs) to surface shared infrastructure.

    Pure logic, no external lookups -- correlates what's already been
    extracted from the email by Task 1's parser and this module's own
    url_intelligence() results.
    """
    url_intel = url_intel or []
    correlations = []

    originating_ip = email.get("originating_ip")
    from_domain = str(email.get("from_addr", "")).split("@")[-1].lower()

    url_hosts = set()

    for entry in url_intel:
        url_value = entry.get("url")
        if not url_value:
            continue

        try:
            host = (urlparse(url_value).hostname or "").lower()
        except Exception:
            continue

        if host:
            url_hosts.add(host)

        if entry.get("ip_based") and originating_ip and host == originating_ip:
            correlations.append({
                "source": url_value,
                "target": originating_ip,
                "relationship": "hosted_on_same_ip_as_sender",
                "note": "The link in this email points directly to the same IP that sent it.",
            })

        if host and from_domain and host == from_domain:
            correlations.append({
                "source": url_value,
                "target": from_domain,
                "relationship": "matches_sender_domain",
                "note": "The link's domain matches the sender's domain.",
            })

        if host and from_domain and host != from_domain and not entry.get("ip_based"):
            correlations.append({
                "source": from_domain,
                "target": host,
                "relationship": "sender_domain_differs_from_link_domain",
                "note": "The sender's domain and the link's domain don't match -- common in spoofed emails.",
            })

    domains = set(url_hosts)
    if from_domain:
        domains.add(from_domain)
    domains.discard("")

    return {
        "ioc_summary": {
            "ips": [originating_ip] if originating_ip else [],
            "domains": sorted(domains),
            "urls": [e["url"] for e in url_intel if e.get("url")],
        },
        "correlations": correlations,
        "correlation_count": len(correlations),
    }


def hash_intelligence(sha256_value: str | None, filename: str | None = None) -> dict:
    """Describe what's known about a file hash.

    No malware-intelligence provider is configured yet, so this always
    returns 'unknown' -- but the output shape is ready to plug in a real
    provider (e.g. VirusTotal) later without changing callers.
    """
    result = {
        "sha256": sha256_value,
        "filename": filename,
        "reputation": "unknown",
        "lookup_status": "not_configured",
        "lookup_provider": None,
        "risk_indicators": [],
    }

    if not sha256_value:
        result["risk_indicators"].append("No file hash was supplied")
        return result

    return result


def domain_intelligence(domain_value: str | None) -> dict:
    """Describe what's known about a domain, offline-safe.

    Real domain age/registrar data requires a WHOIS/RDAP provider that
    isn't configured yet -- per project policy we report 'unknown' rather
    than fabricate an age. Typosquat similarity against known brands is
    computed locally and needs no external lookup.
    """
    result = {
        "domain": domain_value,
        "age_days": None,
        "age_status": "unavailable",
        "registrar": None,
        "typosquat": False,
        "closest_brand_match": None,
        "reputation": "unknown",
        "risk_indicators": [],
    }

    if not domain_value:
        result["risk_indicators"].append("No domain supplied")
        return result

    domain_value = domain_value.lower().strip()
    result["domain"] = domain_value

    best_ratio = 0.0
    best_brand = None
    for brand in KNOWN_BRAND_DOMAINS:
        if domain_value == brand:
            continue
        ratio = difflib.SequenceMatcher(None, domain_value, brand).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_brand = brand

    if best_ratio >= 0.75:
        result["typosquat"] = True
        result["closest_brand_match"] = best_brand
        result["risk_indicators"].append(
            f"Domain closely resembles known brand '{best_brand}' (similarity {round(best_ratio, 2)}) without being an exact match"
        )

    if domain_value in KNOWN_BRAND_DOMAINS:
        result["reputation"] = "known_legitimate"
    elif result["typosquat"]:
        result["reputation"] = "suspicious"

    return result


def behavioural_anomaly(email: dict, history: list[dict] | None = None) -> dict:
    """Transparent sender-baseline anomaly score (0–1), usable without ML retraining."""
    history = history or []
    if not history:
        return {"score": 0.0, "baseline_samples": 0, "signals": [],
                "note": "No sender history supplied; behavioural score not applied."}
    sender = email.get("from_addr", "").lower()
    sender_history = [row for row in history if row.get("from_addr", "").lower() == sender]
    if not sender_history:
        return {"score": 0.35, "baseline_samples": 0, "signals": ["Sender has no prior baseline"],
                "note": "New-sender signal only; collect more history before relying on it."}
    signals, score = [], 0.0
    countries = {str(row.get("country_code", "")).upper() for row in sender_history if row.get("country_code")}
    country = str((email.get("geo_context") or {}).get("country_code", "")).upper()
    if country and countries and country not in countries:
        score += 0.45
        signals.append("Sender location differs from its historical country baseline")
    expected_domains = {str(row.get("reply_to_domain", "")).lower() for row in sender_history if row.get("reply_to_domain")}
    reply_domain = str(email.get("reply_to_addr", "")).split("@")[-1].lower()
    if expected_domains and reply_domain not in expected_domains:
        score += 0.30
        signals.append("Reply-To domain differs from this sender's normal baseline")
    try:
        hour = datetime.now(timezone.utc).hour
        usual_hours = {int(row["hour_utc"]) for row in sender_history if row.get("hour_utc") is not None}
        if usual_hours and hour not in usual_hours:
            score += 0.15
            signals.append("Message arrived outside the sender's usual UTC sending hours")
    except (TypeError, ValueError):
        pass
    return {"score": round(min(score, 1.0), 3), "baseline_samples": len(sender_history),
            "signals": signals, "note": "Transparent baseline comparison."}