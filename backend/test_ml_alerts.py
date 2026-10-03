import pytest

from main import classify_email_ml, get_alerts, push_alert


def test_classifier_detects_phishing_language():
    result = classify_email_ml(
        "Urgent action required: verify your password immediately to prevent account suspension."
    )

    assert result["classification"] in {"phishing", "suspicious"}
    assert result["confidence"] == pytest.approx(
        max(result["probabilities"].values())
    )
    assert sum(result["probabilities"].values()) == pytest.approx(1.0, abs=0.001)


def test_alert_feed_tracks_high_risk_event():
    before = len(get_alerts())
    alert = push_alert(
        "high_risk",
        "Urgent phishing email analyzed",
        "high",
        {"score": 90, "classification": "phishing"},
    )

    assert alert["severity"] == "high"
    assert len(get_alerts()) == before + 1
