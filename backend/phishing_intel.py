"""Optional PhishTank URL checks with bounded requests and an in-process cache."""

import os
import ipaddress
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import requests


PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_CACHE = {}
PHISHTANK_CACHE_LOCK = threading.Lock()
PHISHTANK_CACHE_TTL = 21600


def _normalize_url(value):
    try:
        parsed = urlsplit(str(value).strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None
        hostname = parsed.hostname.lower()
        try:
            address = ipaddress.ip_address(hostname)
            if not address.is_global:
                return None
        except ValueError:
            if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith((".local", ".internal", ".test")):
                return None
        host = f"[{hostname}]" if ":" in hostname else hostname
        port = parsed.port
        if port:
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
    except (TypeError, ValueError):
        return None


def _truthy(value):
    return value is True or str(value).strip().lower() in {"true", "yes", "y", "1"}


def _lookup(url, api_key):
    now = time.monotonic()
    with PHISHTANK_CACHE_LOCK:
        cached = PHISHTANK_CACHE.get(url)
        if cached and cached["expires_at"] > now:
            return dict(cached["result"])

    try:
        response = requests.post(
            PHISHTANK_API_URL,
            data={"url": url, "format": "json", "app_key": api_key},
            headers={"User-Agent": "Threatloom/1.0 (SIH email threat analysis)"},
            timeout=6,
        )
        response.raise_for_status()
        result_data = response.json().get("results", {})
        in_database = _truthy(result_data.get("in_database"))
        verified = _truthy(result_data.get("verified"))
        valid = _truthy(result_data.get("valid"))
        result = {
            "status": "found" if in_database and verified and valid else "not_found",
            "verified": verified,
            "valid": valid,
            "phish_id": result_data.get("phish_id") if in_database else None,
            "detail_url": result_data.get("phish_detail_page") if in_database else None,
            "verified_at": result_data.get("verified_at") if in_database else None,
        }
        cache_ttl = PHISHTANK_CACHE_TTL
    except Exception:
        result = {"status": "unavailable"}
        cache_ttl = 300

    with PHISHTANK_CACHE_LOCK:
        PHISHTANK_CACHE[url] = {"expires_at": now + cache_ttl, "result": result}
        if len(PHISHTANK_CACHE) > 10000:
            for key in [
                key for key, value in PHISHTANK_CACHE.items()
                if value["expires_at"] <= now
            ]:
                PHISHTANK_CACHE.pop(key, None)
            while len(PHISHTANK_CACHE) > 9000:
                PHISHTANK_CACHE.pop(next(iter(PHISHTANK_CACHE)))
    return dict(result)


def check_phishtank_urls(urls):
    """Check a small number of exact URLs; never submit URLs unless configured."""
    values = list(dict.fromkeys(str(url) for url in (urls or []) if url))
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()
    if not api_key:
        return {
            "source_status": "not_configured",
            "checks": [{"url": url, "status": "not_configured"} for url in values],
        }

    try:
        max_checks = int(os.getenv("PHISHTANK_MAX_URL_CHECKS", "1"))
    except ValueError:
        max_checks = 1
    max_checks = max(1, min(max_checks, 3))

    checks = []
    checked_count = 0
    unavailable_count = 0
    for url in values:
        normalized = _normalize_url(url)
        if not normalized:
            checks.append({"url": url, "status": "skipped_invalid_url"})
            continue
        if checked_count >= max_checks:
            checks.append({"url": url, "status": "not_checked_limit"})
            continue
        result = _lookup(normalized, api_key)
        checked_count += 1
        if result.get("status") == "unavailable":
            unavailable_count += 1
        checks.append({"url": url, **result})

    completed = checked_count - unavailable_count
    if checked_count == 0:
        source_status = "not_needed"
    elif completed:
        source_status = "available"
    else:
        source_status = "unavailable"
    return {"source_status": source_status, "checks": checks}
