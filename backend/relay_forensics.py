"""Conservative anomaly checks for untrusted email Received headers."""

import ipaddress
from collections import defaultdict
from datetime import timedelta, timezone
from email.utils import parsedate_to_datetime
import re


PUBLIC_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def analyze_relay_path(received_headers, relay_path):
    anomalies = []
    parsed_dates = []
    public_ip_hops = defaultdict(set)
    invalid_ip_tokens = set()

    for hop_index, header in enumerate(received_headers):
        date_value = str(header).rsplit(";", 1)[-1].strip()
        try:
            received_at = parsedate_to_datetime(date_value)
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=timezone.utc)
            parsed_dates.append((hop_index, received_at.astimezone(timezone.utc)))
        except (TypeError, ValueError, OverflowError):
            continue

        for token in PUBLIC_IPV4_PATTERN.findall(str(header)):
            try:
                address = ipaddress.ip_address(token)
            except ValueError:
                invalid_ip_tokens.add(token)
                continue
            if address.is_global:
                public_ip_hops[token].add(hop_index + 1)

    for (newer_index, newer_time), (older_index, older_time) in zip(parsed_dates, parsed_dates[1:]):
        # Received headers are normally prepended, so a newer header should not
        # claim a time substantially earlier than the next older header.
        if older_index > newer_index and newer_time < older_time - timedelta(minutes=5):
            anomalies.append({
                "code": "received_timestamp_order",
                "severity": "Medium",
                "summary": "Received-header timestamps do not follow newest-to-oldest order.",
                "evidence": f"Hop {newer_index + 1} is timestamped {newer_time.isoformat()} before hop {older_index + 1} at {older_time.isoformat()}.",
            })
            break

    for ip, hop_indexes in public_ip_hops.items():
        if len(hop_indexes) >= 3:
            hops = ", ".join(str(index) for index in sorted(hop_indexes))
            anomalies.append({
                "code": "repeated_relay_ip",
                "severity": "Medium",
                "summary": "The same public IP appears in three or more Received headers.",
                "evidence": f"{ip} appears in hops {hops}; repeated infrastructure can also be legitimate.",
            })

    if len(received_headers) > 12:
        anomalies.append({
            "code": "long_relay_chain",
            "severity": "Low",
            "summary": "The message has an unusually long Received-header chain.",
            "evidence": f"{len(received_headers)} Received headers were present; forwarding lists can also create long chains.",
        })

    if invalid_ip_tokens:
        tokens = ", ".join(sorted(invalid_ip_tokens)[:5])
        anomalies.append({
            "code": "invalid_ip_literal",
            "severity": "Low",
            "summary": "An IP-like value in a Received header is not a valid IPv4 address.",
            "evidence": tokens,
        })

    return {
        "status": "flagged" if anomalies else ("no_anomaly_detected" if received_headers else "insufficient_data"),
        "hop_count": len(relay_path),
        "timestamps_parsed": len(parsed_dates),
        "public_ips_observed": len(public_ip_hops),
        "anomalies": anomalies,
        "note": (
            "These checks look for header-chain inconsistencies. Received headers can be forged, "
            "and legitimate clock skew or forwarding can produce the same patterns."
        ),
    }
