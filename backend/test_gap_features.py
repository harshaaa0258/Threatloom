import hashlib
import json
import sqlite3

import infrastructure_intel
from chain_of_custody import (
    append_evidence_event,
    get_evidence_bundle,
    initialize_evidence_tables,
    sha256_bytes,
)
from main import build_investigation_relationship_graph
from message_patterns import analyze_bec_patterns, analyze_obfuscated_urls
from privacy_controls import mask_sensitive_data
from relay_forensics import analyze_relay_path


def test_relay_path_flags_timestamp_order_anomaly():
    headers = [
        "Received: from relay-a (203.0.113.8); Sat, 03 Oct 2026 10:00:00 +0000",
        "Received: from relay-b (198.51.100.9); Sat, 03 Oct 2026 11:00:00 +0000",
    ]

    result = analyze_relay_path(headers, [])

    assert result["status"] == "flagged"
    assert any(
        item["code"] == "received_timestamp_order"
        for item in result["anomalies"]
    )


def test_url_and_bec_analysis_return_explainable_signals():
    text = (
        "The CEO needs the invoice paid today by wire transfer to the new bank "
        "details. Do not call; keep this confidential."
    )
    url_analysis = analyze_obfuscated_urls(
        ["https://xn--80ak6aa92e.example/path", "https://bit.ly/example"],
        "<a href='https://evil.example/login'>https://trusted.example/login</a>",
        resolve_shorteners=False,
    )

    bec = analyze_bec_patterns(
        text,
        {"from": "CEO <ceo@company.example>", "reply-to": "billing@fraud.example"},
        url_analysis=url_analysis,
        urls=["https://bit.ly/example"],
    )

    url_signal_types = {
        signal["type"]
        for item in url_analysis["urls"]
        for signal in item["signals"]
    }
    bec_signal_types = {signal["type"] for signal in bec["signals"]}
    assert "punycode_domain" in url_signal_types
    assert url_analysis["link_text_signals"]
    assert {"reply_to_mismatch", "payment_diversion_language", "executive_impersonation_pattern"} <= bec_signal_types


def test_infrastructure_checks_local_indicators_without_network(monkeypatch):
    monkeypatch.setattr(
        infrastructure_intel,
        "_get_tor_exit_addresses",
        lambda: ({"8.8.8.8"}, "available"),
    )
    monkeypatch.setattr(
        infrastructure_intel,
        "_get_feodo_c2_addresses",
        lambda: ({"1.1.1.1"}, "available"),
    )
    monkeypatch.setattr(
        infrastructure_intel,
        "_check_abuseipdb",
        lambda ip: {"status": "not_configured", "ip": ip},
    )
    monkeypatch.setenv("BOTNET_C2_IPS", "1.1.1.1")
    monkeypatch.setenv("OPEN_RELAY_IPS", "9.9.9.9")

    result = infrastructure_intel.build_infrastructure_intelligence([
        {"ip": "8.8.8.8", "is_proxy": False, "is_hosting": False},
        {"ip": "1.1.1.1", "is_proxy": False, "is_hosting": False},
        {"ip": "9.9.9.9", "is_proxy": False, "is_hosting": False},
    ])

    types = {item["type"] for item in result["indicators"]}
    assert {"Tor exit node", "Botnet C2 indicator", "Configured open relay indicator"} <= types


def test_privacy_masking_masks_email_and_ip():
    result = mask_sensitive_data(
        {"sender": "analyst@example.com", "origin": "8.8.8.8"},
        {"mask_email_addresses": True, "mask_ip_addresses": True},
    )

    assert result == {"sender": "a***@example.com", "origin": "8.8.xxx.xxx"}


def test_evidence_bundle_verifies_hash_chain_and_preserved_source(tmp_path):
    database = str(tmp_path / "evidence.db")
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE investigations (id INTEGER PRIMARY KEY)")
    initialize_evidence_tables(connection)
    connection.commit()
    connection.close()

    source = b"From: sender@example.com\r\n\r\nSuspicious message"
    append_evidence_event(
        database,
        investigation_id=7,
        event_type="message_received",
        source_sha256=sha256_bytes(source),
        analysis_text_sha256=hashlib.sha256(source).hexdigest(),
        byte_length=len(source),
        source_content=source,
        preserve_source=True,
    )

    bundle = get_evidence_bundle(database, 7)

    assert bundle is not None
    assert bundle["ledger_integrity"]["verified"] is True
    assert bundle["source"]["artifact_verified"] is True
    assert bundle["source"]["artifact_status"] == "verified"


def test_relationship_graph_correlates_shared_sender_and_ip():
    investigations = [
        {
            "id": 1,
            "sender": "sender@example.com",
            "origin_ip": "8.8.8.8",
            "result_json": json.dumps({
                "headers": {"from": "sender@example.com"},
                "candidate_origin_ip": "8.8.8.8",
            }),
        },
        {
            "id": 2,
            "sender": "SENDER@example.com",
            "origin_ip": "8.8.8.8",
            "result_json": json.dumps({
                "headers": {"from": "SENDER@example.com"},
                "candidate_origin_ip": "8.8.8.8",
            }),
        },
    ]

    graph = build_investigation_relationship_graph(investigations)

    assert graph["summary"]["investigations_analyzed"] == 2
    assert graph["summary"]["repeated_entities"] == 3
    assert graph["summary"]["repeated_relationships"] >= 1
