import base64
import hashlib
import json
import sqlite3

import infrastructure_intel
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
import main as main_module

from chain_of_custody import (
    append_evidence_event,
    get_evidence_bundle,
    initialize_evidence_tables,
    sha256_bytes,
)
from attribution_assessment import build_attribution_assessment
from dkim_verification import verify_dkim_signatures
from main import (
    ReviewedTrainingDataError,
    _load_ml_training_data,
    authenticate_evidence_actor,
    build_campaign_suggestions,
    build_investigation_relationship_graph,
)
from message_patterns import analyze_bec_patterns, analyze_obfuscated_urls
from privacy_controls import mask_sensitive_data
from relay_forensics import analyze_relay_path


def test_dkim_verification_cryptographically_checks_message_bytes(monkeypatch):
    signed_message = base64.b64decode(
        "REtJTS1TaWduYXR1cmU6IHY9MTsgYT1yc2Etc2hhMjU2OyBjPXJlbGF4ZWQvc2ltcGxlOyBkPWV4YW1wbGUuY29tOw0K"
        "IGk9QGV4YW1wbGUuY29tOyBxPWRucy90eHQ7IHM9c2VsZWN0b3I7IHQ9MTc5MTA1MTc4MjsgaD1mcm9tIDogc3ViamVjdDsN"
        "CiBiaD1xazFhUHdsRWxtaFB0Q2JycWRGK0liMGlVaTJiQnQrazJZUXpJNEt3ZExjPTsNCiBiPUR4ZE5xQ1NLS3dKMGRremZN"
        "ZzJOeUcwK0RjYzg5dkpRVlJXZXJJeDc2KzFBejNoYkl5TUR4RDV1cVY4ZVAzNUZtQUNvcQ0KIFBLcXo0SVZvZWdleFJ0bWtR"
        "SGtBRnZnbnB4dTBickZLUVg3UjkyOW1NdFVVWkpvekI4dWVCeXdrbVAvSC8xaHJDT3ZzMTNsDQogQzhoNDRDMW5pSThobzUxb"
        "FBKUnVIQUJrYi9idFhXZz0NCkZyb206IHNlbmRlckBleGFtcGxlLmNvbQ0KU3ViamVjdDogVGVzdCBES0lNDQoNCk9yaWdpbmFs"
        "IGJvZHkNCg=="
    )
    dns_record = (
        b"v=DKIM1; k=rsa; "
        b"p=MIGJAoGBAILPwvtLsDhCJZcW4HxFDirwww5XklHnTjGHT1h8BvOYo4NgzVdQhZbxLkh0oEhB4E1Pwjd4i9yddNmCQ9VQyNQtlTD8elOxX9nTiIR20uT5CBjB46KAezT3IjMtJ6dkB5F0z+VXs2dYOe/mTS+iLoYVSx/uP37T8r/BGyaxgpIHAgMBAAE="
    )

    def dnsfunc(name, timeout=5):
        if name.rstrip(b".") == b"selector._domainkey.example.com":
            return dns_record
        return None

    result = verify_dkim_signatures(signed_message, dnsfunc=dnsfunc)
    assert result["status"] == "pass"
    assert result["domain"] == "example.com"
    assert result["selector"] == "selector"
    assert result["signatures"][0]["status"] == "pass"

    tampered = verify_dkim_signatures(
        signed_message.replace(b"Original body", b"Changed body"),
        dnsfunc=dnsfunc,
    )
    assert tampered["status"] == "fail"
    assert tampered["signatures"][0]["status"] == "fail"

    monkeypatch.setattr(
        main_module,
        "verify_dkim_signatures",
        lambda raw_message: verify_dkim_signatures(raw_message, dnsfunc=dnsfunc),
    )
    monkeypatch.setattr(main_module, "check_dmarc", lambda domain: {"status": "found"})
    monkeypatch.setattr(
        main_module,
        "build_attribution_assessment",
        lambda *args, **kwargs: {"status": "not_available"},
    )
    analysis = main_module._analyze_email(
        main_module.EmailRequest(
            email=signed_message.decode("ascii"),
            source_file_base64=base64.b64encode(signed_message).decode("ascii"),
        ),
        mask_response=False,
        persist=False,
        allow_external_lookups=False,
    )

    assert analysis["dkim"]["status"] == "pass"
    assert analysis["dkim"]["alignment"] == "aligned"
    assert analysis["dmarc_evaluation"]["status"] == "pass"


def test_dkim_verification_reports_dns_or_crypto_errors(monkeypatch):
    class FailingVerifier:
        def __init__(self, message):
            pass

        def verify(self, idx):
            raise TimeoutError("DNS lookup timed out")

    monkeypatch.setattr("dkim_verification.dkim.DKIM", FailingVerifier)
    message = (
        b"From: sender@example.com\r\n"
        b"DKIM-Signature: v=1; d=example.com; s=selector; b=signature\r\n"
        b"\r\nbody"
    )

    result = verify_dkim_signatures(message)

    assert result["status"] == "error"
    assert result["signatures"][0]["error"] == "DNS lookup timed out"


def test_dkim_verification_bounds_header_work(monkeypatch):
    class InvalidVerifier:
        def __init__(self, message):
            pass

        def verify(self, idx):
            return False

    monkeypatch.setattr("dkim_verification.dkim.DKIM", InvalidVerifier)
    headers = "\r\n".join(
        "DKIM-Signature: v=1; d=example.com; s=selector; b=signature"
        for _ in range(6)
    )
    message = f"From: sender@example.com\r\n{headers}\r\n\r\nbody".encode()

    result = verify_dkim_signatures(message)

    assert result["status"] == "partial"
    assert result["verification_limited"] is True
    assert len(result["signatures"]) == 5


def test_dkim_verification_handles_absent_signature():
    result = verify_dkim_signatures(b"From: sender@example.com\r\n\r\nbody")

    assert result["status"] == "not_present"
    assert result["signatures"] == []


def test_failed_dkim_signature_reduces_attribution_assessment(tmp_path):
    database = str(tmp_path / "attribution.db")
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE investigations (
            id INTEGER PRIMARY KEY,
            sender TEXT,
            origin_ip TEXT,
            result_json TEXT
        )
        """
    )
    connection.commit()
    connection.close()

    assessment = build_attribution_assessment(
        database,
        {"from": "sender@example.com"},
        spf_result=None,
        dkim_result={"status": "fail", "alignment": "aligned"},
        dmarc_evaluation={"status": "fail"},
        candidate_origin_ip=None,
        candidate_origin_intelligence=None,
        relay_path_analysis=None,
    )

    failure = next(
        signal
        for signal in assessment["signals"]
        if signal["type"] == "authentication_failure"
    )
    assert failure["points"] == -10


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


def test_open_relay_ip_feed_file_supports_comments(tmp_path, monkeypatch):
    feed = tmp_path / "open-relays.txt"
    feed.write_text("# verified relay list\n9.9.9.9\ninvalid\n", encoding="utf-8")
    monkeypatch.delenv("OPEN_RELAY_IPS", raising=False)
    monkeypatch.setenv("OPEN_RELAY_IPS_FILE", str(feed))

    assert infrastructure_intel._configured_ip_feed("OPEN_RELAY_IPS") == {"9.9.9.9"}


def test_reviewed_ml_data_mode_refuses_synthetic_fallback(monkeypatch):
    monkeypatch.setenv("EMAIL_ML_REQUIRE_REVIEWED_DATA", "true")
    monkeypatch.delenv("EMAIL_ML_TRAINING_CSV", raising=False)
    monkeypatch.setattr(main_module.classify_email_ml, "_model", None, raising=False)
    monkeypatch.setattr(
        main_module.classify_email_ml,
        "_training_metadata",
        {},
        raising=False,
    )

    with pytest.raises(ReviewedTrainingDataError, match="EMAIL_ML_TRAINING_CSV is not configured"):
        _load_ml_training_data()
    monkeypatch.setattr(main_module, "LogisticRegression", None)
    with pytest.raises(ReviewedTrainingDataError, match="scikit-learn is unavailable"):
        main_module.classify_email_ml("A test email")
    response = TestClient(main_module.app).post(
        "/analyze",
        json={"email": "Subject: reviewed-data enforcement test\n\nNo URLs are present."},
    )
    assert response.status_code == 503


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
    assert bundle["events"][0]["actor_is_authenticated"] is False

    append_evidence_event(
        database,
        investigation_id=7,
        event_type="reviewed",
        actor="verified-reviewer",
        actor_is_authenticated=True,
    )
    updated_bundle = get_evidence_bundle(database, 7)
    assert updated_bundle is not None
    assert updated_bundle["events"][1]["actor_is_authenticated"] is True


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


def test_campaign_suggestions_group_shared_strong_indicators():
    rows = [
        {
            "id": 1,
            "sender": "finance@example.com",
            "subject": "Updated invoice",
            "result_json": json.dumps({
                "headers": {"from": "finance@example.com"},
                "candidate_origin_ip": "8.8.8.8",
                "url_domains": ["pay.example"],
            }),
        },
        {
            "id": 2,
            "sender": "finance@example.com",
            "subject": "Payment details changed",
            "result_json": json.dumps({
                "headers": {"from": "finance@example.com"},
                "candidate_origin_ip": "8.8.8.8",
                "url_domains": ["pay.example"],
            }),
        },
        {
            "id": 3,
            "sender": "unrelated@example.net",
            "subject": "Unrelated",
            "result_json": json.dumps({
                "headers": {"from": "unrelated@example.net"},
                "candidate_origin_ip": "1.1.1.1",
            }),
        },
    ]

    suggestions = build_campaign_suggestions(rows)

    assert len(suggestions) == 1
    assert suggestions[0]["investigation_ids"] == [1, 2]
    assert {item["type"] for item in suggestions[0]["shared_indicators"]} >= {
        "sender",
        "origin_ip",
        "url_domain",
    }


def test_campaign_suggestion_endpoint_creates_reviewable_case(tmp_path, monkeypatch):
    database = str(tmp_path / "campaigns.db")
    monkeypatch.setattr(main_module, "DB_PATH", database)
    main_module.init_database()
    connection = sqlite3.connect(database)
    for investigation_id in (1, 2):
        result = {
            "headers": {"from": "finance@example.com"},
            "candidate_origin_ip": "8.8.8.8",
        }
        connection.execute(
            """
            INSERT INTO investigations (
                id, created_at, sender, subject, threat_score, risk_level,
                classification, origin_ip, result_json
            ) VALUES (?, datetime('now'), ?, ?, 70, 'high', 'phishing', ?, ?)
            """,
            (
                investigation_id,
                "finance@example.com",
                f"Invoice {investigation_id}",
                "8.8.8.8",
                json.dumps(result),
            ),
        )
    connection.commit()
    connection.close()
    append_evidence_event(
        database,
        investigation_id=1,
        event_type="message_received",
        source_sha256="source-hash",
        analysis_text_sha256="analysis-hash",
        byte_length=12,
    )
    token = "campaign-api-test-token-with-at-least-32-chars"
    monkeypatch.setenv(
        "EVIDENCE_ACTOR_TOKENS",
        json.dumps({"reviewer@example.org": token}),
    )

    client = TestClient(main_module.app)
    response = client.get("/campaigns/suggestions")
    assert response.status_code == 200
    suggestions = response.json()["suggestions"]
    assert len(suggestions) == 1

    created = client.post(
        "/campaigns/from-suggestion",
        json={
            "title": "Invoice campaign",
            "investigation_ids": suggestions[0]["investigation_ids"],
        },
    )
    assert created.status_code == 200
    case = client.get(f"/cases/{created.json()['case_id']}")
    event = client.post(
        "/investigations/1/evidence/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"event_type": "reviewed", "notes": "Reviewed after test."},
    )

    assert case.status_code == 200
    assert {item["id"] for item in case.json()["investigations"]} == {1, 2}
    assert event.status_code == 200
    assert event.json()["event"]["actor"] == "reviewer@example.org"
    assert event.json()["event"]["actor_is_authenticated"] is True


def test_evidence_actor_authentication_uses_configured_identity(monkeypatch):
    token = "test-only-token-with-more-than-32-characters"
    monkeypatch.setenv(
        "EVIDENCE_ACTOR_TOKENS",
        json.dumps({"reviewer@example.org": token}),
    )

    assert authenticate_evidence_actor(f"Bearer {token}") == "reviewer@example.org"

    with pytest.raises(HTTPException) as invalid:
        authenticate_evidence_actor("Bearer invalid-token")
    assert invalid.value.status_code == 401

    monkeypatch.delenv("EVIDENCE_ACTOR_TOKENS", raising=False)
    with pytest.raises(HTTPException) as unconfigured:
        authenticate_evidence_actor(f"Bearer {token}")
    assert unconfigured.value.status_code == 503
