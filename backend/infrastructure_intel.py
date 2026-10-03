"""Infrastructure indicator lookups used by the email analysis API."""

import ipaddress
import os
import re
import threading
import time

import requests


TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_EXIT_CACHE = {"addresses": set(), "expires_at": 0.0, "status": "not_loaded"}
TOR_EXIT_CACHE_LOCK = threading.Lock()
ABUSEIPDB_CACHE = {}
ABUSEIPDB_CACHE_LOCK = threading.Lock()


def _is_public_ip(value):
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def _configured_ip_feed(environment_name):
    addresses = set()
    raw = os.getenv(environment_name, "").strip()
    for value in re.split(r"[,;\s]+", raw):
        if not value:
            continue
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return addresses


def _get_tor_exit_addresses():
    """Fetch the Tor Project's bulk list and reuse it for six hours."""
    now = time.monotonic()
    with TOR_EXIT_CACHE_LOCK:
        if TOR_EXIT_CACHE["expires_at"] > now:
            return set(TOR_EXIT_CACHE["addresses"]), TOR_EXIT_CACHE["status"]

        try:
            response = requests.get(TOR_EXIT_LIST_URL, timeout=5)
            response.raise_for_status()
            addresses = set()
            for line in response.text.splitlines():
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                try:
                    addresses.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
            if not addresses:
                raise ValueError("Tor exit list was empty or unreadable")

            TOR_EXIT_CACHE.update({
                "addresses": addresses,
                "expires_at": now + 21600,
                "status": "available",
            })
        except Exception:
            TOR_EXIT_CACHE["expires_at"] = now + 900
            TOR_EXIT_CACHE["status"] = "stale_cache" if TOR_EXIT_CACHE["addresses"] else "unavailable"

        return set(TOR_EXIT_CACHE["addresses"]), TOR_EXIT_CACHE["status"]


def _check_abuseipdb(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "not_configured", "ip": ip}

    now = time.monotonic()
    with ABUSEIPDB_CACHE_LOCK:
        cached = ABUSEIPDB_CACHE.get(ip)
        if cached and cached["expires_at"] > now:
            return dict(cached["result"])
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            result = {
                "status": "found",
                "abuse_confidence_score": data.get("abuseConfidenceScore"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "total_reports": data.get("totalReports"),
                "last_reported_at": data.get("lastReportedAt"),
            }
            ABUSEIPDB_CACHE[ip] = {"expires_at": now + 21600, "result": result}
            return dict(result)
        except Exception:
            return {"status": "unavailable"}


def build_infrastructure_intelligence(ip_records):
    """Add sourced infrastructure context without treating hosting as proof of abuse."""
    records = [
        record for record in ip_records
        if isinstance(record, dict) and record.get("ip") and _is_public_ip(record["ip"])
    ]
    abuse_results = {}
    for record in records[:5]:
        abuse_results[str(record["ip"])] = _check_abuseipdb(str(record["ip"]))

    # Download the list once per cache window so local IP comparison still works
    # when a separate provider misses or mislabels a Tor exit address.
    tor_candidates = bool(records)
    tor_addresses, tor_status = _get_tor_exit_addresses() if tor_candidates else (set(), "not_needed")
    botnet_ips = _configured_ip_feed("BOTNET_C2_IPS")
    open_relay_ips = _configured_ip_feed("OPEN_RELAY_IPS")
    indicators = []
    seen = {"tor": set(), "proxy": set(), "hosting": set(), "abuse": set(), "botnet": set(), "open_relay": set()}

    for record in records:
        ip = str(record["ip"])
        abuse = abuse_results.get(ip, {})
        tor_list_match = ip in tor_addresses
        abuse_tor_match = abuse.get("is_tor") is True

        if tor_list_match or abuse_tor_match:
            seen["tor"].add(ip)
            source = "Tor Project exit list" if tor_list_match else "AbuseIPDB"
            indicators.append({
                "type": "Tor exit node",
                "value": ip,
                "severity": "Medium",
                "confidence": "high" if tor_list_match else "medium",
                "source": source,
                "reason": f"{source} identifies this address as a Tor exit. This is an infrastructure signal, not proof of sender identity.",
            })
        elif record.get("is_proxy") is True:
            seen["proxy"].add(ip)
            indicators.append({
                "type": "VPN / proxy infrastructure",
                "value": ip,
                "severity": "Informational",
                "confidence": "medium",
                "source": "IP-API",
                "reason": "IP-API flags this address as proxy, VPN, or Tor infrastructure; this field does not distinguish those categories.",
            })

        usage_type = str(abuse.get("usage_type") or "")
        ip_api_hosting = record.get("is_hosting") is True
        abuse_hosting = "data center/web hosting" in usage_type.lower()
        if ip_api_hosting or abuse_hosting:
            seen["hosting"].add(ip)
            sources = [name for name, matched in (("IP-API", ip_api_hosting), ("AbuseIPDB", abuse_hosting)) if matched]
            indicators.append({
                "type": "Cloud / hosted infrastructure",
                "value": ip,
                "severity": "Informational",
                "confidence": "medium",
                "source": ", ".join(sources),
                "reason": "The address is associated with hosting or a data center. Hosting alone is not malicious evidence.",
            })

        abuse_score = abuse.get("abuse_confidence_score")
        if isinstance(abuse_score, (int, float)) and abuse_score >= 25:
            seen["abuse"].add(ip)
            indicators.append({
                "type": "Reported abusive IP",
                "value": ip,
                "severity": "High" if abuse_score >= 75 else "Medium",
                "confidence": "medium",
                "source": "AbuseIPDB",
                "reason": f"AbuseIPDB reports an abuse-confidence score of {abuse_score} from reports in the last 90 days; reports are not attribution proof.",
            })

        if ip in botnet_ips:
            seen["botnet"].add(ip)
            indicators.append({
                "type": "Configured botnet C2 indicator",
                "value": ip,
                "severity": "High",
                "confidence": "high",
                "source": "BOTNET_C2_IPS configuration",
                "reason": "This address matched the operator-configured botnet command-and-control IP list.",
            })

        if ip in open_relay_ips:
            seen["open_relay"].add(ip)
            indicators.append({
                "type": "Configured open relay indicator",
                "value": ip,
                "severity": "High",
                "confidence": "high",
                "source": "OPEN_RELAY_IPS configuration",
                "reason": "This address matched the operator-configured open SMTP relay IP list.",
            })

    abuse_status = "disabled" if not os.getenv("ABUSEIPDB_API_KEY") else (
        "available" if any(result.get("status") == "found" for result in abuse_results.values()) else "unavailable"
    )
    fields_available = any(
        record.get("is_proxy") is not None or record.get("is_hosting") is not None
        for record in records
    )
    return {
        "summary": {
            "ips_checked": len(records),
            "tor_exit_ips": len(seen["tor"]),
            "vpn_or_proxy_ips": len(seen["proxy"]),
            "hosting_ips": len(seen["hosting"]),
            "abuse_reported_ips": len(seen["abuse"]),
            "botnet_c2_ips": len(seen["botnet"]),
            "open_relay_ips": len(seen["open_relay"]),
            "abuseipdb_ips_checked": sum(result.get("status") == "found" for result in abuse_results.values()),
        },
        "source_status": {
            "ip_api_proxy_hosting": "available" if fields_available else "unavailable",
            "tor_project_exit_list": tor_status,
            "abuseipdb": abuse_status,
            "botnet_c2_list": "configured" if botnet_ips else "not_configured",
            "open_relay_list": "configured" if open_relay_ips else "not_configured",
        },
        "indicators": indicators,
        "note": (
            "VPN/proxy and hosting labels describe infrastructure type, not intent. "
            "Botnet C2 and open-relay matches are checked only when the corresponding "
            "operator-maintained IP lists are configured."
        ),
    }
