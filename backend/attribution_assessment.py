"""Conservative sender-domain and origin evidence consistency assessment."""

import json
import sqlite3
from email.utils import getaddresses


def _address_parts(value: str | None) -> tuple[set[str], set[str]]:
    addresses = getaddresses([str(value or "")])
    emails = {address.strip().lower() for _, address in addresses if "@" in address}
    domains = {email.rsplit("@", 1)[-1].strip(" .>") for email in emails}
    return emails, domains


def _stored_reply_domains(result_json: str) -> set[str]:
    try:
        result = json.loads(result_json or "{}")
        return _address_parts((result.get("headers") or {}).get("reply-to"))[1]
    except (TypeError, ValueError, AttributeError):
        return set()


def build_attribution_assessment(
    db_path: str,
    headers: dict,
    spf_result: dict | None,
    dkim_result: dict | None,
    dmarc_evaluation: dict | None,
    candidate_origin_ip: str | None,
    candidate_origin_intelligence: dict | None,
    relay_path_analysis: dict | None,
) -> dict:
    sender_addresses, sender_domains = _address_parts(headers.get("from"))
    reply_addresses, reply_domains = _address_parts(headers.get("reply-to"))
    _, return_domains = _address_parts(headers.get("return-path"))
    sender_domain = next(iter(sender_domains), "")
    score = 0
    signals = []

    dmarc_status = str((dmarc_evaluation or {}).get("status") or "").lower()
    spf_status = str((spf_result or {}).get("status") or "").lower()
    spf_aligned = str((spf_result or {}).get("alignment") or "").lower() == "aligned"
    dkim_status = str((dkim_result or {}).get("status") or "").lower()
    dkim_aligned = str((dkim_result or {}).get("alignment") or "").lower() == "aligned"

    if dmarc_status == "pass":
        score += 30
        signals.append({"type": "aligned_domain_authentication", "effect": "supports", "points": 30, "detail": "DMARC evaluation reports an aligned authentication pass for the visible sender domain."})
    else:
        auth_points = 0
        if spf_status == "pass" and spf_aligned:
            auth_points += 20
            signals.append({"type": "aligned_spf", "effect": "supports", "points": 20, "detail": "SPF passed with alignment to the visible sender domain."})
        if dkim_status in {"verified", "pass"} and dkim_aligned:
            auth_points += 15
            signals.append({"type": "verified_aligned_dkim", "effect": "supports", "points": 15, "detail": "DKIM reports cryptographic verification and alignment."})
        score += min(auth_points, 30)
        if dmarc_status == "fail" or spf_status in {"fail", "softfail", "permerror"}:
            score -= 10
            signals.append({"type": "authentication_failure", "effect": "reduces", "points": -10, "detail": "An authentication evaluation failed or did not align with the visible sender domain."})
        if dkim_status == "key_found":
            signals.append({"type": "dkim_not_verified", "effect": "neutral", "points": 0, "detail": "A DKIM public key was found, but the message signature was not cryptographically verified."})

    if sender_domains and reply_domains:
        if sender_domains.intersection(reply_domains):
            score += 10
            signals.append({"type": "reply_to_consistent", "effect": "supports", "points": 10, "detail": "Reply-To uses a domain observed in the visible From address."})
        else:
            score -= 10
            signals.append({"type": "reply_to_mismatch", "effect": "reduces", "points": -10, "detail": "Reply-To and visible From domains differ."})

    if sender_domains and return_domains:
        if sender_domains.intersection(return_domains):
            score += 8
            signals.append({"type": "return_path_consistent", "effect": "supports", "points": 8, "detail": "Return-Path uses a domain observed in the visible From address."})
        else:
            score -= 5
            signals.append({"type": "return_path_mismatch", "effect": "reduces", "points": -5, "detail": "Return-Path and visible From domains differ."})

    if candidate_origin_ip:
        score += 10
        signals.append({"type": "candidate_origin_available", "effect": "supports", "points": 10, "detail": "A candidate public origin IP was extracted from the Received path."})
        if (candidate_origin_intelligence or {}).get("status") == "found":
            score += 5
            signals.append({"type": "origin_network_enriched", "effect": "supports", "points": 5, "detail": "The candidate origin IP has network intelligence available."})

    anomalies = (relay_path_analysis or {}).get("anomalies") or []
    if (relay_path_analysis or {}).get("status") == "no_anomaly_detected":
        score += 5
        signals.append({"type": "no_relay_anomaly_observed", "effect": "supports", "points": 5, "detail": "No configured relay-path anomaly rule was triggered; this does not prove the headers are authentic."})
    elif anomalies:
        score -= min(10, 3 * len(anomalies))
        signals.append({"type": "relay_anomalies", "effect": "reduces", "points": -min(10, 3 * len(anomalies)), "detail": f"{len(anomalies)} relay-path anomaly signal(s) reduce confidence in the header-derived origin."})

    prior_rows = []
    if sender_addresses or sender_domains or candidate_origin_ip or reply_addresses:
        connection = sqlite3.connect(db_path)
        try:
            prior_rows = connection.execute(
                "SELECT id, sender, origin_ip, result_json FROM investigations ORDER BY id DESC LIMIT 500"
            ).fetchall()
        finally:
            connection.close()

    correlated = []
    exact_sender_count = 0
    domain_count = 0
    origin_ip_count = 0
    reply_alias_count = 0
    correlated_total = 0
    for investigation_id, previous_sender, previous_ip, result_json in prior_rows:
        previous_addresses, previous_domains = _address_parts(previous_sender)
        previous_reply_domains = _stored_reply_domains(result_json)
        matches = []
        if sender_addresses.intersection(previous_addresses):
            exact_sender_count += 1
            matches.append("same_sender_address")
        elif sender_domains.intersection(previous_domains):
            domain_count += 1
            matches.append("same_sender_domain")
        if candidate_origin_ip and previous_ip == candidate_origin_ip:
            origin_ip_count += 1
            matches.append("same_candidate_origin_ip")
        if reply_domains.intersection(previous_reply_domains):
            reply_alias_count += 1
            matches.append("same_reply_to_domain")
        if matches:
            correlated_total += 1
        if matches and len(correlated) < 20:
            correlated.append({"investigation_id": investigation_id, "matching_indicators": matches})

    correlation_points = min(15, exact_sender_count * 4 + domain_count * 2 + origin_ip_count * 4 + reply_alias_count * 2)
    if correlation_points:
        score += correlation_points
        signals.append({
            "type": "prior_investigation_correlation",
            "effect": "supports",
            "points": correlation_points,
            "detail": f"Related sender or infrastructure indicators appeared in {correlated_total} saved investigation(s) within the 500-record search window.",
        })

    score = max(0, min(100, score))
    label = "High" if score >= 65 else "Moderate" if score >= 35 else "Low"
    return {
        "status": "assessment_available" if signals else "insufficient_evidence",
        "confidence_score": score,
        "confidence_label": label,
        "candidate_sender_domain": sender_domain or None,
        "candidate_origin_ip": candidate_origin_ip,
        "signals": signals,
        "correlated_investigations": correlated,
        "correlation_counts": {
            "same_sender_address": exact_sender_count,
            "same_sender_domain": domain_count,
            "same_candidate_origin_ip": origin_ip_count,
            "same_reply_to_domain": reply_alias_count,
            "search_window": min(500, len(prior_rows)),
        },
        "note": (
            "This score measures consistency of sender-domain and origin indicators, not the probability of fraud or proof of a natural person's identity. "
            "The candidate origin is inferred from Received headers, and DKIM points are awarded only if cryptographic verification is available."
        ),
    }
