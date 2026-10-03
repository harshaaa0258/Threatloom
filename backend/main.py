from xml.sax.saxutils import escape
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from email import policy
from email.parser import BytesParser
import dns.resolver
import requests
import ipaddress
import asyncio
import csv
import re
import base64
import hashlib
import json
import logging
from dotenv import load_dotenv
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
from email.utils import getaddresses
from collections import Counter
from fastapi.responses import Response, StreamingResponse
from urllib.parse import urlsplit
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

try:
    from .infrastructure_intel import build_infrastructure_intelligence
except ImportError:
    from infrastructure_intel import build_infrastructure_intelligence

try:
    from .relay_forensics import analyze_relay_path
except ImportError:
    from relay_forensics import analyze_relay_path

try:
    from .message_patterns import analyze_bec_patterns, analyze_obfuscated_urls
except ImportError:
    from message_patterns import analyze_bec_patterns, analyze_obfuscated_urls

try:
    from .chain_of_custody import (
        append_evidence_event,
        get_evidence_bundle,
        get_verified_source_artifact,
        initialize_evidence_tables,
        purge_source_artifact,
        sha256_bytes,
    )
except ImportError:
    from chain_of_custody import (
        append_evidence_event,
        get_evidence_bundle,
        get_verified_source_artifact,
        initialize_evidence_tables,
        purge_source_artifact,
        sha256_bytes,
    )

try:
    from .attribution_assessment import build_attribution_assessment
except ImportError:
    from attribution_assessment import build_attribution_assessment

try:
    from .privacy_controls import (
        get_privacy_settings,
        initialize_privacy_settings,
        mask_sensitive_data,
        update_privacy_settings,
    )
except ImportError:
    from privacy_controls import (
        get_privacy_settings,
        initialize_privacy_settings,
        mask_sensitive_data,
        update_privacy_settings,
    )

try:
    from .domain_fingerprints import fingerprint_hosting, lookup_traditional_whois
except ImportError:
    from domain_fingerprints import fingerprint_hosting, lookup_traditional_whois

try:
    from .phishing_intel import check_phishtank_urls
except ImportError:
    from phishing_intel import check_phishtank_urls

try:
    from .gmail_monitor import GmailInboxMonitor
except ImportError:
    from gmail_monitor import GmailInboxMonitor

try:
    import spf
except ImportError:  # pragma: no cover - optional runtime dependency in some environments
    spf = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
except ImportError:  # pragma: no cover - optional ML dependency until installed
    TfidfVectorizer = None
    LogisticRegression = None
    FeatureUnion = None
    Pipeline = None

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
app = FastAPI(title="MailCipherX-AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:3000",
    "https://harshavardhannagandla0306-ship-it.github.io",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailRequest(BaseModel):
    email: str
    source_file_base64: str | None = None


class CaseCreateRequest(BaseModel):
    title: str
    description: str = ""
    tags: list[str] | None = None


class CaseUpdateRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    tags: list[str] | None = None


class EvidenceEventRequest(BaseModel):
    event_type: str
    actor: str = "unattributed"
    notes: str = ""


class PrivacySettingsUpdate(BaseModel):
    retention_days: int | None = None
    mask_email_addresses: bool | None = None
    mask_ip_addresses: bool | None = None


ALERT_STORE = []
_ML_MODEL = None


def push_alert(event_type: str, summary: str, severity: str, payload: dict | None = None):
    """Persist an alert for the REST feed and any connected SSE clients."""
    created_at = datetime.now(timezone.utc).isoformat()
    connection = sqlite3.connect(DB_PATH, timeout=10)
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO alert_events (created_at, event_type, summary, severity, payload_json) VALUES (?, ?, ?, ?, ?)",
        (created_at, event_type, summary, severity.lower(), json.dumps(payload or {}, default=str)),
    )
    alert_id = cursor.lastrowid
    connection.commit()
    connection.close()
    alert = {
        "id": alert_id,
        "type": event_type,
        "summary": summary,
        "severity": severity.lower(),
        "created_at": created_at,
        "payload": payload or {},
    }
    ALERT_STORE.append(alert)
    return alert


def get_alerts(limit: int = 20):
    limit = max(1, min(limit, 100))
    connection = sqlite3.connect(DB_PATH)
    rows = connection.execute(
        "SELECT id, created_at, event_type, summary, severity, payload_json FROM alert_events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    connection.close()
    return [
        {
            "id": row[0],
            "created_at": row[1],
            "type": row[2],
            "summary": row[3],
            "severity": row[4],
            "payload": json.loads(row[5] or "{}"),
        }
        for row in rows
    ]


def get_alerts_after(last_id: int, limit: int = 100):
    limit = max(1, min(limit, 500))
    connection = sqlite3.connect(DB_PATH)
    rows = connection.execute(
        "SELECT id, created_at, event_type, summary, severity, payload_json FROM alert_events WHERE id > ? ORDER BY id ASC LIMIT ?",
        (last_id, limit),
    ).fetchall()
    connection.close()
    return [
        {
            "id": row[0],
            "created_at": row[1],
            "type": row[2],
            "summary": row[3],
            "severity": row[4],
            "payload": json.loads(row[5] or "{}"),
        }
        for row in rows
    ]


def _build_ml_training_data():
    return [
        ("Hi team, thanks for the update. The project is moving ahead as planned.", "legitimate"),
        ("Good afternoon, please review the attached report at your convenience before Thursday's meeting.", "legitimate"),
        ("The revised agenda is attached. Let me know if you would like another topic added.", "legitimate"),
        ("Your order has shipped. The carrier expects delivery on Friday; no action is required.", "legitimate"),
        ("This is the receipt for the subscription renewal you completed today. Contact support through our usual portal with questions.", "legitimate"),
        ("I have shared the notes from our planning call in the team workspace.", "legitimate"),
        ("The monthly statement is ready in online banking. Sign in using your saved bookmark to view it.", "legitimate"),
        ("Your meeting room changed to Building A, room 204. The calendar invitation has been updated.", "legitimate"),
        ("Please confirm whether the attached draft matches the figures from our approved purchase order.", "legitimate"),
        ("The support case you opened has been updated. Reply to the existing ticket if you need more help.", "legitimate"),
        ("Urgent security alert: verify your password now to avoid account suspension.", "phishing"),
        ("Action required: your account will be locked unless you sign in and confirm your credentials immediately.", "phishing"),
        ("This is a final warning. Click here to verify your identity before the deadline today.", "phishing"),
        ("Your mailbox has suspicious activity. Click the secure login link and update your username and password.", "phishing"),
        ("We blocked your email access. Open the attached sign-in page and enter your current password to restore service.", "phishing"),
        ("Your cloud storage is full. Log in through this link within 30 minutes or your files will be deleted.", "phishing"),
        ("A new device was added to your account. If this was not you, use this form to cancel and provide your recovery code.", "phishing"),
        ("Your payroll deposit is pending. Confirm your employee password and bank login on the linked verification page.", "phishing"),
        ("We could not deliver your package. Pay a small redelivery fee and submit your card details at the link below.", "phishing"),
        ("The secure document share expired. Enter your corporate credentials to read the invoice attachment.", "phishing"),
        ("Payment required immediately. We need the invoice confirmation and bank account details before noon.", "fraud"),
        ("Please review the wire transfer change and share your verification details to process the payment.", "fraud"),
        ("I am traveling and cannot call. Purchase gift cards for the client and send me the codes as soon as possible.", "fraud"),
        ("Our supplier changed banks. Send today's outstanding balance to the new account listed in this message.", "fraud"),
        ("The attached invoice is overdue. Ignore the purchase order process and wire the funds before close of business.", "fraud"),
        ("Please split the payment into two transfers so our finance review will not delay the confidential transaction.", "fraud"),
        ("We overpaid your account. Return the difference by wire transfer to the account below and keep this private.", "fraud"),
        ("I need you to change the vendor bank details in the payment system before the scheduled batch runs.", "fraud"),
        ("Send the deal deposit today to secure the property. The signed paperwork will arrive after the transfer.", "fraud"),
        ("Your refund is approved. Provide your card number and online banking code so we can release the funds.", "fraud"),
        ("The system detected unusual activity. Please review the notice and contact the help desk if you do not recognize it.", "suspicious"),
        ("Can you confirm which account should receive the next payment? I could not match it to the last statement.", "suspicious"),
        ("Please open the document and let me know whether you can access it. I will resend through the shared drive if needed.", "suspicious"),
        ("We need a quick response about the updated contact information before the directory is finalized.", "suspicious"),
        ("The attachment contains a form requesting your department and work phone. Check with HR if you did not expect it.", "suspicious"),
        ("A vendor is asking us to use a different payment portal. Verify the request with procurement before changing anything.", "suspicious"),
        ("Your password expires soon. Use the company bookmark to review the notice, and contact IT if it looks unfamiliar.", "suspicious"),
        ("Please reply with a convenient time to discuss your account. We will not ask for your password by email.", "suspicious"),
        ("A shared file is waiting for review. Check the sender and expected project before opening the link.", "suspicious"),
        ("This message refers to a security review but does not identify the affected service or a support case number.", "suspicious"),
        ("From: Microsoft Security <account@microsoft-support-check.example> Your Microsoft account needs a password reset now.", "impersonated"),
        ("The display name says PayPal Support, but the sender address is billing@paypa1-alerts.example. Confirm your card details.", "impersonated"),
        ("DocuSign requested a document signature from a lookalike domain. Sign in to review the confidential contract.", "impersonated"),
        ("Google Workspace admin notice from google-security-review.example: confirm your password to keep mail active.", "impersonated"),
        ("A message using the CEO's name asks payroll to update direct deposit details and keep the change confidential.", "impersonated"),
        ("The vendor's familiar logo appears in the message, but the Reply-To address is a free webmail account.", "impersonated"),
        ("Your bank's name is in the subject, while the sender domain is an unrelated registration created for this notice.", "impersonated"),
        ("A copied Microsoft invoice asks you to pay a new account that does not match the supplier's approved records.", "impersonated"),
        ("The sender claims to be the company help desk and asks for a one-time login code over email.", "impersonated"),
        ("A message signed by the finance director requests an urgent gift-card purchase and forbids calling to verify.", "impersonated"),
    ]


def _load_ml_training_data():
    """Use a configured labeled CSV when available, otherwise the demo seed corpus."""
    seed_data = _build_ml_training_data()
    seed_counts = dict(Counter(label for _, label in seed_data))
    seed_metadata = {
        "source": "built_in_demo_seed",
        "training_samples": len(seed_data),
        "class_counts": seed_counts,
        "warning": "The built-in corpus is synthetic demonstration data. Configure EMAIL_ML_TRAINING_CSV with reviewed labeled examples before relying on classifications.",
    }
    dataset_path = os.getenv("EMAIL_ML_TRAINING_CSV", "").strip()
    if not dataset_path:
        return seed_data, seed_metadata

    try:
        if os.path.getsize(dataset_path) > 25 * 1024 * 1024:
            raise ValueError("Configured CSV exceeds the 25 MB limit.")
        rows = []
        with open(dataset_path, "r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if not reader.fieldnames or not {"text", "label"}.issubset(reader.fieldnames):
                raise ValueError("Configured CSV must have text and label columns.")
            for row in reader:
                text = str(row.get("text") or "").strip()
                label = str(row.get("label") or "").strip().lower()
                if text and len(text) <= 50000 and label in {"legitimate", "suspicious", "impersonated", "phishing", "fraud"}:
                    rows.append((text, label))
                if len(rows) >= 20000:
                    break
        counts = dict(Counter(label for _, label in rows))
        if len(rows) < 15 or len(counts) < 2 or any(count < 3 for count in counts.values()):
            raise ValueError("Configured CSV needs at least 15 examples and three examples per label.")
        return rows, {
            "source": "configured_csv",
            "training_samples": len(rows),
            "class_counts": counts,
        }
    except (OSError, UnicodeError, csv.Error, ValueError):
        return seed_data, {
            **seed_metadata,
            "warning": "Configured training CSV could not be used; the built-in demonstration corpus was used.",
        }


def classify_email_ml(email_text: str, headers: dict | None = None, urls: list | None = None):
    """Train a local word/character TF-IDF classifier for email-threat triage."""
    text = (email_text or "").strip()
    if not text:
        return {
            "model": "TF-IDF + logistic regression",
            "classification": "legitimate",
            "confidence": 0.0,
            "probabilities": {},
            "training_source": "not_run",
            "training_samples": 0,
            "class_counts": {},
            "confidence_note": "No message text was supplied.",
        }

    suspicious_terms = {
        "urgent": 2,
        "verify": 2,
        "password": 3,
        "immediately": 2,
        "account": 1,
        "secure": 1,
        "login": 2,
        "click": 2,
        "suspicious": 2,
        "invoice": 2,
        "wire": 2,
        "bank": 2,
        "payment": 2,
    }

    lower = text.lower()
    score = sum(weight for term, weight in suspicious_terms.items() if term in lower)

    if TfidfVectorizer and LogisticRegression and FeatureUnion:
        model = getattr(classify_email_ml, "_model", None)
        if model is None:
            training_data, training_metadata = _load_ml_training_data()
            model = Pipeline([
                ("features", FeatureUnion([
                    ("word", TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True, max_features=20000)),
                    ("character", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, max_features=20000)),
                ])),
                ("clf", LogisticRegression(max_iter=1500, class_weight="balanced", solver="liblinear")),
            ])
            model.fit([sample for sample, _ in training_data], [label for _, label in training_data])
            classify_email_ml._model = model
            classify_email_ml._training_metadata = training_metadata

        prediction = model.predict([text])[0]
        probabilities = model.predict_proba([text])[0]
        confidence = float(max(probabilities))
        label = str(prediction).lower()
        if label not in {"legitimate", "suspicious", "impersonated", "phishing", "fraud"}:
            label = "suspicious"
        training_metadata = getattr(classify_email_ml, "_training_metadata", {})
        return {
            "model": "Word + character TF-IDF logistic regression",
            "classification": label,
            "confidence": round(confidence, 4),
            "probabilities": {cls: round(float(prob), 4) for cls, prob in zip(model.classes_, probabilities)},
            "training_source": training_metadata.get("source", "unknown"),
            "training_samples": training_metadata.get("training_samples", 0),
            "class_counts": training_metadata.get("class_counts", {}),
            "training_warning": training_metadata.get("warning"),
            "confidence_note": "The predicted-class score is not calibrated and is a triage signal, not a probability that the email is malicious.",
        }

    if any(term in lower for term in ("display name mismatch", "lookalike sender", "impersonating", "paypa1", "micr0soft", "g00gle")):
        classification = "impersonated"
        confidence = 0.74
    elif score >= 8 or "verify your password" in lower or "account suspended" in lower:
        classification = "phishing"
        confidence = 0.9
    elif score >= 4:
        classification = "suspicious"
        confidence = 0.74
    elif "invoice" in lower or "payment" in lower:
        classification = "fraud"
        confidence = 0.7
    else:
        classification = "legitimate"
        confidence = 0.65

    return {
        "model": "Rule-based fallback (scikit-learn unavailable)",
        "classification": classification,
        "confidence": round(confidence, 4),
        "probabilities": {},
        "training_source": "rule_fallback",
        "training_samples": 0,
        "class_counts": {},
        "confidence_note": "This fallback score is a rule-strength heuristic, not a calibrated model probability.",
    }


def analyze_email_nlp(email_text: str, headers: dict, urls: list):
    """AI-assisted, explainable NLP analysis for email threat language.

    This is intentionally a lightweight local NLP layer. It extracts semantic
    threat patterns without claiming that the score is a probability of attack
    or pretending that a trained ML model is being used.
    """
    text = email_text or ""
    lower = text.lower()

    categories = {
        "urgency": [
            "urgent", "immediately", "act now", "within 24 hours",
            "final warning", "expires today", "account will be suspended",
            "account suspended", "account locked",
        ],
        "credential_harvesting": [
            "password", "username and password", "login credentials",
            "verify your account", "verify your identity", "sign in",
            "signin", "authenticate", "authentication required",
        ],
        "financial_fraud": [
            "payment required", "invoice", "refund", "bank account",
            "credit card", "wire transfer", "gift card", "payment",
        ],
        "social_engineering": [
            "verify", "confirm your identity", "security alert",
            "unusual activity", "suspicious activity", "click here",
            "do not ignore", "action required", "failure to comply",
        ],
    }

    category_matches = {}
    for category, phrases in categories.items():
        matches = [phrase for phrase in phrases if phrase in lower]
        if matches:
            category_matches[category] = matches

    # Look for a display-name / domain mismatch that is useful to NLP context.
    from_value = str((headers or {}).get("from") or "")
    reply_to = str((headers or {}).get("reply-to") or "")
    brand_context = []
    brand_patterns = {
        "Microsoft": ["microsoft", "micr0soft"],
        "Google": ["google", "g00gle"],
        "Apple": ["apple", "app1e"],
        "PayPal": ["paypal", "paypa1"],
        "Amazon": ["amazon", "amaz0n"],
    }
    sender_context = from_value.lower()
    for brand, patterns in brand_patterns.items():
        if any(pattern in sender_context for pattern in patterns):
            brand_context.append(brand)

    suspicious_url_context = []
    url_words = [
        "login", "signin", "verify", "verification", "account",
        "secure", "password", "authenticate", "update",
    ]
    for url in urls or []:
        url_lower = str(url).lower()
        matches = [word for word in url_words if word in url_lower]
        if matches:
            suspicious_url_context.append({
                "url": str(url),
                "signals": matches,
            })

    mismatch = False
    if "@" in from_value and "@" in reply_to:
        sender_domain = from_value.rsplit("@", 1)[-1].replace(">", "").strip().lower()
        reply_domain = reply_to.rsplit("@", 1)[-1].replace(">", "").strip().lower()
        mismatch = bool(sender_domain and reply_domain and sender_domain != reply_domain)

    signal_points = 0
    category_weights = {
        "urgency": 20,
        "credential_harvesting": 30,
        "financial_fraud": 20,
        "social_engineering": 20,
    }
    for category, matches in category_matches.items():
        signal_points += min(len(matches) * 5, category_weights[category])
    if suspicious_url_context:
        signal_points += min(len(suspicious_url_context) * 10, 20)
    if mismatch:
        signal_points += 15
    if brand_context:
        signal_points += 10
    signal_points = min(signal_points, 100)

    if category_matches.get("credential_harvesting") and suspicious_url_context:
        primary_threat = "Credential phishing"
    elif category_matches.get("financial_fraud"):
        primary_threat = "Financial fraud / payment scam"
    elif category_matches.get("credential_harvesting"):
        primary_threat = "Credential harvesting"
    elif category_matches.get("urgency") and category_matches.get("social_engineering"):
        primary_threat = "Social engineering"
    elif suspicious_url_context:
        primary_threat = "Suspicious link-based social engineering"
    elif category_matches:
        primary_threat = "Suspicious social engineering"
    else:
        primary_threat = "No strong NLP threat pattern detected"

    if signal_points >= 70:
        assessment = "Strong threat-language indicators"
    elif signal_points >= 40:
        assessment = "Moderate threat-language indicators"
    elif signal_points > 0:
        assessment = "Limited threat-language indicators"
    else:
        assessment = "No strong threat-language indicators"

    return {
        "engine": "AI-assisted NLP pattern analysis",
        "assessment": assessment,
        "signal_score": signal_points,
        "primary_threat": primary_threat,
        "categories": category_matches,
        "brand_context": brand_context,
        "reply_to_domain_mismatch": mismatch,
        "suspicious_url_context": suspicious_url_context,
        "note": (
            "This NLP layer extracts explainable language and context signals. "
            "The signal score is not a probability of maliciousness and does not "
            "represent a trained-model accuracy claim."
        ),
    }

def check_spf(domain: str):
    try:
        resolver = dns.resolver.Resolver()

        # Use public DNS resolvers
        resolver.nameservers = [
            "8.8.8.8",
            "1.1.1.1",
        ]

        resolver.timeout = 3
        resolver.lifetime = 6

        answers = resolver.resolve(domain, "TXT")

        for answer in answers:
            record = answer.to_text().strip('"')

            if record.startswith("v=spf1"):
                return {
                    "status": "found",
                    "record": record,
                }

        return {
            "status": "not_found",
            "record": None,
        }

    except Exception as e:
        return {
            "status": "error",
            "record": None,
            "error": str(e),
        }
def check_dkim(domain: str, selector: str):
    try:
        resolver = dns.resolver.Resolver()

        resolver.nameservers = [
            "8.8.8.8",
            "1.1.1.1",
        ]

        resolver.timeout = 3
        resolver.lifetime = 6

        dkim_domain = f"{selector}._domainkey.{domain}"

        answers = resolver.resolve(dkim_domain, "TXT")

        records = []

        for answer in answers:
            record = answer.to_text().strip('"')
            records.append(record)

        return {
            "status": "key_found",
            "domain": domain,
            "selector": selector,
            "dns_name": dkim_domain,
            "records": records,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "key_not_found",
            "domain": domain,
            "selector": selector,
            "dns_name": dkim_domain,
        }

    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "selector": selector,
            "dns_name": dkim_domain,
            "error": str(e),
        }
def check_dmarc(domain: str):
    try:
        resolver = dns.resolver.Resolver()

        resolver.nameservers = [
            "8.8.8.8",
            "1.1.1.1",
        ]

        resolver.timeout = 3
        resolver.lifetime = 6

        dmarc_domain = f"_dmarc.{domain}"

        answers = resolver.resolve(dmarc_domain, "TXT")

        for answer in answers:
            record = answer.to_text().strip('"')

            if record.lower().startswith("v=dmarc1"):
                return {
                    "status": "found",
                    "domain": domain,
                    "dns_name": dmarc_domain,
                    "record": record,
                }

        return {
            "status": "not_found",
            "domain": domain,
            "dns_name": dmarc_domain,
        }

    except dns.resolver.NXDOMAIN:
        return {
            "status": "not_found",
            "domain": domain,
            "dns_name": dmarc_domain,
        }

    except Exception as e:
        return {
            "status": "error",
            "domain": domain,
            "dns_name": dmarc_domain,
            "error": str(e),
        }   
def domains_align(domain1: str, domain2: str):
    if not domain1 or not domain2:
        return False
    return domain1.lower().strip(".") == domain2.lower().strip(".")   
def evaluate_dmarc(
    from_domain: str,
    spf_result: dict | None,
    dkim_result: dict | None,
):
    spf_pass_aligned = (
        spf_result is not None
        and spf_result.get("status") == "pass"
        and spf_result.get("alignment") == "aligned"
    )

    dkim_pass_aligned = (
        dkim_result is not None
        and dkim_result.get("status") == "pass"
        and dkim_result.get("alignment") == "aligned"
    )

    if spf_pass_aligned or dkim_pass_aligned:
        return {
            "status": "pass",
            "from_domain": from_domain,
            "spf_aligned": spf_pass_aligned,
            "dkim_aligned": dkim_pass_aligned,
            "reason": "At least one aligned authentication mechanism passed."
        }

    return {
        "status": "fail",
        "from_domain": from_domain,
        "spf_aligned": spf_pass_aligned,
        "dkim_aligned": dkim_pass_aligned,
        "reason": "Neither SPF nor DKIM passed with alignment."
    }
def extract_urls(email_text: str):
    url_pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(
        url_pattern,
        email_text,
        re.IGNORECASE
    )

    # Remove duplicates while preserving order
    unique_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url not in unique_urls:
            unique_urls.append(url)

    return unique_urls 
from urllib.parse import urlparse


def extract_url_domains(urls: list[str]):
    domains = []

    for url in urls:
        try:
            hostname = urlparse(url).hostname

            if hostname:
                hostname = hostname.lower()

                if hostname not in domains:
                    domains.append(hostname)

        except Exception:
            continue

    return domains


def check_domain_intelligence(domain: str, include_whois: bool = False):
    """Collect passive DNS + RDAP registration intelligence for a domain."""
    domain = (domain or "").strip().lower().rstrip(".")

    result = {
        "domain": domain,
        "status": "ok",
        "dns": {},
        "rdap": {},
        "signals": [],
    }

    if not domain:
        result["status"] = "invalid"
        return result

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 3
    resolver.lifetime = 6

    for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(domain, record_type)
            values = [answer.to_text().strip('\"') for answer in answers]
            result["dns"][record_type] = values
        except Exception:
            result["dns"][record_type] = []

    # Passive registration data through the public RDAP service.
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=8,
        )

        if response.status_code == 200:
            data = response.json()
            events = data.get("events", [])
            event_map = {}
            for event in events:
                action = event.get("eventAction")
                date = event.get("eventDate")
                if action and date:
                    event_map[action] = date

            registrar = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if len(item) >= 4 and item[0] in ("fn", "org"):
                                registrar = item[3]
                                break
                    if registrar:
                        break

            nameservers = []
            for ns in data.get("nameservers", []):
                name = ns.get("ldhName")
                if name:
                    nameservers.append(name)

            result["rdap"] = {
                "status": "found",
                "registrar": registrar,
                "created": event_map.get("registration"),
                "updated": event_map.get("last changed") or event_map.get("last update of RDAP database"),
                "expires": event_map.get("expiration"),
                "status_codes": data.get("status", []),
                "nameservers": nameservers,
            }

            if event_map.get("registration"):
                result["signals"].append("Domain registration date is available from RDAP.")
            else:
                result["signals"].append("RDAP returned no registration date.")
        elif response.status_code == 404:
            result["rdap"] = {"status": "not_found"}
            result["signals"].append("No RDAP registration record was found for this domain.")
        else:
            result["rdap"] = {"status": "error", "http_status": response.status_code}
            result["signals"].append("RDAP lookup could not be completed.")
    except Exception as e:
        result["rdap"] = {"status": "error", "message": str(e)}
        result["signals"].append("RDAP lookup could not be completed.")

    if result["rdap"].get("status") == "found":
        for field in ["registrar", "created", "updated", "expires", "nameservers"]:
            result[field] = result["rdap"].get(field)

    result["hosting_fingerprint"] = fingerprint_hosting(result["dns"])
    if include_whois:
        result["whois"] = lookup_traditional_whois(domain)
        if result["whois"].get("status") == "found":
            summary = result["whois"].get("registrar") or "Registrar unavailable"
            if result["whois"].get("created"):
                summary += f"; created {result['whois']['created']}"
            result["signals"].append(f"Traditional WHOIS registration details: {summary}.")
        else:
            result["signals"].append(
                "Traditional WHOIS status is "
                f"{result['whois'].get('status', 'unavailable')}; RDAP remains the registration fallback."
            )
    for observation in result["hosting_fingerprint"].get("observations", []):
        result["signals"].append(
            f"Passive DNS {observation['category'].replace('_', ' ')} fingerprint suggests "
            f"{observation['provider']} via {observation['indicator']}."
        )

    if not any(result["dns"].get(record) for record in ["A", "AAAA", "CNAME", "MX", "NS"]):
        result["signals"].append("No common DNS records were returned for this domain.")

    if not result["dns"].get("MX"):
        result["signals"].append("No MX record was found for this domain.")

    return result


def analyze_attachment_metadata(filename: str | None, content_type: str | None, size: int):
    """Classify an email attachment using metadata only. Never executes attachment content."""
    filename = filename or "unnamed"
    content_type = content_type or "application/octet-stream"
    name_lower = filename.lower().strip()

    dangerous_extensions = {
        ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse",
        ".vbs", ".vbe", ".ps1", ".msi", ".dll", ".hta", ".jar",
        ".wsf", ".wsh", ".reg"
    }
    script_extensions = {
        ".js", ".jse", ".vbs", ".vbe", ".ps1", ".hta", ".wsf", ".wsh"
    }
    archive_extensions = {".zip", ".rar", ".7z", ".iso", ".img"}
    document_extensions = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".docm", ".xlsm", ".pptm"
    }

    suffixes = re.findall(r"\.[a-z0-9]{1,10}", name_lower)
    extension = suffixes[-1] if suffixes else ""

    signals = []
    risk = "Low"
    points = 0

    if extension in dangerous_extensions:
        risk = "Critical"
        points = 25
        signals.append("Executable or script attachment type detected.")
    elif extension in archive_extensions:
        risk = "Medium"
        points = 10
        signals.append("Archive attachment can contain additional files that require inspection.")
    elif extension in document_extensions:
        risk = "Medium"
        points = 5
        signals.append("Office document attachment detected; macros or embedded content may require inspection.")

    # Detect filenames such as invoice.pdf.exe or image.jpg.js.
    if len(suffixes) >= 2 and suffixes[-1] in dangerous_extensions:
        risk = "Critical"
        points = max(points, 30)
        signals.append("Double-extension filename can disguise an executable or script.")

    suspicious_name_words = [
        "invoice", "payment", "refund", "password", "credential",
        "security", "verify", "urgent", "update", "account"
    ]
    matched_words = [word for word in suspicious_name_words if word in name_lower]
    if matched_words and extension in dangerous_extensions:
        points = min(points + 5, 35)
        signals.append(
            "Suspicious filename keywords detected: " + ", ".join(matched_words)
        )

    executable_mime_types = {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
    }
    script_mime = (
        content_type in {
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "text/x-python",
            "text/vbscript",
        }
    )

    if content_type in executable_mime_types or script_mime:
        risk = "Critical"
        points = max(points, 30)
        signals.append("Executable or script MIME type detected.")

    if size > 10 * 1024 * 1024:
        signals.append("Attachment is larger than 10 MB.")
    elif size == 0:
        signals.append("Attachment contains no decoded payload.")

    if risk == "Low" and signals:
        risk = "Medium"

    return {
        "filename": filename,
        "content_type": content_type,
        "size": size,
        "extension": extension or None,
        "risk": risk,
        "risk_points": points,
        "signals": signals,
        "analysis": (
            "Metadata-only attachment analysis. The attachment was not opened or executed."
        ),
    }


def check_virustotal_url(url: str):
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key is not configured."
        }

    try:
        # VirusTotal accepts an unpadded Base64 URL identifier
        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().rstrip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY
            },
            timeout=10
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "url": url,
                "message": "URL has no existing VirusTotal report."
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "url": url,
                "http_status": response.status_code,
                "message": "VirusTotal request failed."
            }

        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "status": "found",
            "url": url,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            )
        }

    except Exception as e:
        return {
            "status": "error",
            "url": url,
            "message": str(e)
        }
def lookup_ip(ip: str):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,query"
            },
            timeout=5,
        )

        data = response.json()

        if data.get("status") == "success":
            return {
                "status": "found",
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "organization": data.get("org"),
                "asn": data.get("as"),
                "as_name": data.get("asname"),
                "is_proxy": data.get("proxy"),
                "is_hosting": data.get("hosting"),
                "location_accuracy": "approximate",
            }

        return {
            "status": "not_found",
            "ip": ip,
            "message": data.get("message"),
        }

    except Exception as e:
        return {
            "status": "error",
            "ip": ip,
            "error": str(e),
        }
def check_virustotal_ip(ip: str):
    if not VIRUSTOTAL_API_KEY:
        return {
            "status": "unavailable",
            "ip": ip,
            "message": "VirusTotal API key is not configured."
        }

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY
            },
            timeout=10,
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "ip": ip,
                "message": "IP address not found in VirusTotal."
            }

        response.raise_for_status()

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "status": "found",
            "ip": ip,
            "reputation": attributes.get("reputation", 0),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    except Exception as e:
        return {
            "status": "error",
            "ip": ip,
            "error": str(e),
        }   
def is_public_ip(ip: str):
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_reserved
            and not address.is_multicast
        )

    except ValueError:
        return False    


def build_threat_intelligence_summary(
    ip_intelligence: list,
    domain_intelligence: list,
    url_intelligence: list,
):
    """Build a transparent threat-intelligence summary from available signals."""
    indicators = []
    malicious_ips = 0
    suspicious_ips = 0
    malicious_urls = 0
    suspicious_urls = 0

    for item in ip_intelligence:
        reputation = item.get("reputation") or {}
        malicious = int(reputation.get("malicious") or 0)
        suspicious = int(reputation.get("suspicious") or 0)

        if malicious > 0:
            malicious_ips += 1
            indicators.append({
                "type": "IP",
                "value": item.get("ip"),
                "severity": "High",
                "reason": f"VirusTotal reported {malicious} malicious detection(s).",
            })
        elif suspicious > 0:
            suspicious_ips += 1
            indicators.append({
                "type": "IP",
                "value": item.get("ip"),
                "severity": "Medium",
                "reason": f"VirusTotal reported {suspicious} suspicious detection(s).",
            })

    for item in url_intelligence:
        malicious = int(item.get("malicious") or 0)
        suspicious = int(item.get("suspicious") or 0)
        phishtank = item.get("phishtank") or {}
        phishtank_match = phishtank.get("status") == "found"

        if malicious > 0:
            malicious_urls += 1
            indicators.append({
                "type": "URL",
                "value": item.get("url"),
                "severity": "High",
                "reason": f"VirusTotal reported {malicious} malicious detection(s).",
            })
        elif suspicious > 0:
            suspicious_urls += 1
            indicators.append({
                "type": "URL",
                "value": item.get("url"),
                "severity": "Medium",
                "reason": f"VirusTotal reported {suspicious} suspicious detection(s).",
            })

        if phishtank_match:
            if malicious == 0:
                malicious_urls += 1
            indicators.append({
                "type": "Verified phishing URL",
                "value": item.get("url"),
                "severity": "High",
                "source": "PhishTank",
                "reason": "PhishTank reports this exact URL as verified and valid phishing. This is an indicator match, not sender attribution.",
            })

    domain_signals = []
    for item in domain_intelligence:
        for signal in item.get("signals", []):
            domain_signals.append({
                "type": "Domain",
                "value": item.get("domain"),
                "severity": "Info",
                "reason": signal,
            })

    indicators.extend(domain_signals)

    phishtank_statuses = [
        (item.get("phishtank") or {}).get("status") for item in url_intelligence
    ]
    if "found" in phishtank_statuses or "not_found" in phishtank_statuses:
        phishtank_status = "available"
    elif "unavailable" in phishtank_statuses:
        phishtank_status = "unavailable"
    elif "not_configured" in phishtank_statuses:
        phishtank_status = "not_configured"
    else:
        phishtank_status = "not_needed"
    phishtank_matches = sum(status == "found" for status in phishtank_statuses)

    if malicious_ips or malicious_urls:
        overall = "High"
    elif suspicious_ips or suspicious_urls:
        overall = "Medium"
    elif ip_intelligence or url_intelligence or domain_intelligence:
        overall = "Informational"
    else:
        overall = "No Data"

    return {
        "overall_status": overall,
        "summary": {
            "ips_checked": len(ip_intelligence),
            "malicious_ips": malicious_ips,
            "suspicious_ips": suspicious_ips,
            "urls_checked": len(url_intelligence),
            "malicious_urls": malicious_urls,
            "suspicious_urls": suspicious_urls,
            "phishtank_matches": phishtank_matches,
            "domains_checked": len(domain_intelligence),
        },
        "source_status": {"phishtank": phishtank_status},
        "indicators": indicators,
        "note": (
            "Threat-intelligence results are external intelligence signals. "
            "A clean result does not prove an indicator is safe, and a detection "
            "does not by itself prove who sent the email."
        ),
    }


def build_investigation_relationship_graph(investigations: list[dict]):
    """Aggregate email identities and infrastructure shared across investigations."""
    nodes = {}
    edges = {}

    def add_node(kind: str, value, investigation_id: int):
        label = str(value or "").strip().lower().rstrip(".")
        if not label:
            return None
        node_id = hashlib.sha256(f"{kind}:{label}".encode("utf-8")).hexdigest()[:20]
        node = nodes.setdefault(node_id, {
            "id": node_id,
            "type": kind,
            "label": label,
            "_investigations": set(),
        })
        node["_investigations"].add(investigation_id)
        return node_id

    def add_edge(source: str | None, target: str | None, relation: str, investigation_id: int):
        if not source or not target or source == target:
            return
        key = (source, target, relation)
        edge = edges.setdefault(key, {
            "source": source,
            "target": target,
            "relation": relation,
            "_investigations": set(),
        })
        edge["_investigations"].add(investigation_id)

    def parsed_emails(value):
        found = []
        for _, address in getaddresses([str(value or "")]):
            address = address.strip().lower()
            if re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", address) and address not in found:
                found.append(address)
        return found

    def normalized_domain(value):
        domain = str(value or "").strip().lower().rstrip(".")
        if domain.startswith("@"):
            domain = domain[1:]
        if len(domain) > 253 or not re.fullmatch(r"[a-z0-9.-]+", domain):
            return None
        if not any(character.isalpha() for character in domain):
            return None
        return domain

    def domains_from_urls(urls):
        found = []
        for item in urls if isinstance(urls, list) else []:
            raw_url = item.get("url") if isinstance(item, dict) else item
            raw_url = str(raw_url or "").strip()
            if not raw_url:
                continue
            parsed = urlsplit(raw_url if "://" in raw_url else f"//{raw_url}")
            domain = normalized_domain(parsed.hostname or "")
            if domain and domain not in found:
                found.append(domain)
        return found

    for row in investigations:
        try:
            investigation_id = int(row.get("id"))
            result = json.loads(row.get("result_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(result, dict):
            continue

        headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
        senders = parsed_emails(headers.get("from") or row.get("sender"))
        recipients = parsed_emails(headers.get("to") or row.get("recipient"))
        reply_to = parsed_emails(headers.get("reply-to"))
        return_path = parsed_emails(headers.get("return-path"))

        sender_nodes = [add_node("email", address, investigation_id) for address in senders]
        recipient_nodes = [add_node("email", address, investigation_id) for address in recipients]
        reply_nodes = [
            add_node("domain", address.rsplit("@", 1)[-1], investigation_id)
            for address in reply_to
        ]
        return_nodes = [
            add_node("domain", address.rsplit("@", 1)[-1], investigation_id)
            for address in return_path
        ]
        sender_domain_nodes = [
            add_node("domain", address.rsplit("@", 1)[-1], investigation_id)
            for address in senders
        ]

        url_domains = result.get("url_domains", [])
        if not isinstance(url_domains, list):
            url_domains = []
        url_domains = [normalized_domain(value) for value in url_domains]
        url_domains.extend(domains_from_urls(result.get("urls", [])))
        url_domain_nodes = list(dict.fromkeys(
            add_node("domain", domain, investigation_id)
            for domain in url_domains if domain
        ))

        raw_ips = result.get("ip_addresses", [])
        if not isinstance(raw_ips, list):
            raw_ips = []
        candidate_ip = result.get("candidate_origin_ip") or row.get("origin_ip")
        if candidate_ip:
            raw_ips.append(candidate_ip)
        ip_nodes = []
        seen_ips = set()
        for raw_ip in raw_ips:
            try:
                ip = str(ipaddress.ip_address(str(raw_ip)))
            except ValueError:
                continue
            if ip not in seen_ips and is_public_ip(ip):
                seen_ips.add(ip)
                ip_nodes.append(add_node("ip", ip, investigation_id))

        for sender_node in sender_nodes:
            for domain_node in sender_domain_nodes:
                add_edge(sender_node, domain_node, "sender_domain", investigation_id)
            for recipient_node in recipient_nodes:
                add_edge(sender_node, recipient_node, "sent_to", investigation_id)
            for reply_node in reply_nodes:
                add_edge(sender_node, reply_node, "reply_to_domain", investigation_id)
            for return_node in return_nodes:
                add_edge(sender_node, return_node, "return_path_domain", investigation_id)
            for ip_node in ip_nodes:
                add_edge(sender_node, ip_node, "observed_origin_ip", investigation_id)

        for domain_node in sender_domain_nodes:
            for url_node in url_domain_nodes:
                add_edge(domain_node, url_node, "linked_url_domain", investigation_id)
            for ip_node in ip_nodes:
                add_edge(domain_node, ip_node, "observed_with_ip", investigation_id)

    output_nodes = []
    for node in nodes.values():
        investigation_ids = sorted(node.pop("_investigations"))
        node["investigation_count"] = len(investigation_ids)
        node["investigation_ids"] = investigation_ids[:10]
        output_nodes.append(node)
    output_edges = []
    for edge in edges.values():
        investigation_ids = sorted(edge.pop("_investigations"))
        edge["investigation_count"] = len(investigation_ids)
        edge["investigation_ids"] = investigation_ids[:10]
        output_edges.append(edge)

    output_nodes.sort(key=lambda node: (-node["investigation_count"], node["type"], node["label"]))
    output_edges.sort(key=lambda edge: (-edge["investigation_count"], edge["relation"], edge["source"]))
    return {
        "nodes": output_nodes,
        "edges": output_edges,
        "summary": {
            "investigations_analyzed": len(investigations),
            "entities": len(output_nodes),
            "relationships": len(output_edges),
            "repeated_entities": sum(node["investigation_count"] > 1 for node in output_nodes),
            "repeated_relationships": sum(edge["investigation_count"] > 1 for edge in output_edges),
        },
        "note": (
            "Relationships show indicators observed together in saved email analyses. "
            "They are leads for review, not proof that an entity controls another."
        ),
    }


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "investigations.db")


def _evidence_artifact_settings():
    preserve_source = os.getenv("PRESERVE_RAW_EVIDENCE", "true").strip().lower() in {"1", "true", "yes"}
    try:
        max_size_mb = int(os.getenv("EVIDENCE_MAX_ARTIFACT_MB", "10"))
    except ValueError:
        max_size_mb = 10
    max_size_mb = max(1, min(max_size_mb, 50))
    return preserve_source, max_size_mb * 1024 * 1024


def _privacy_response(value):
    return mask_sensitive_data(value, get_privacy_settings(DB_PATH))


def _record_evidence_event_if_available(investigation_id: int, event_type: str, actor: str, notes: str):
    connection = sqlite3.connect(DB_PATH)
    exists = connection.execute(
        "SELECT 1 FROM evidence_ledger WHERE investigation_id = ? LIMIT 1",
        (investigation_id,),
    ).fetchone()
    connection.close()
    if exists:
        return append_evidence_event(
            DB_PATH,
            investigation_id,
            event_type,
            actor=actor,
            notes=notes,
        )
    return None


def init_database():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            threat_score INTEGER,
            risk_level TEXT,
            classification TEXT,
            origin_ip TEXT,
            result_json TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            tags_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_investigations (
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            added_at TEXT NOT NULL,
            PRIMARY KEY (case_id, investigation_id)
        )
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS remove_case_memberships_after_investigation_delete
        AFTER DELETE ON investigations
        BEGIN
            DELETE FROM case_investigations WHERE investigation_id = OLD.id;
        END
    """)
    initialize_evidence_tables(connection)
    initialize_privacy_settings(connection)
    connection.commit()
    connection.close()


def run_retention_cleanup():
    settings = get_privacy_settings(DB_PATH)
    retention_days = int(settings.get("retention_days") or 0)
    if retention_days <= 0:
        return {"success": True, "retention_days": 0, "deleted_count": 0, "message": "Automatic retention is disabled."}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    connection = sqlite3.connect(DB_PATH)
    expired_ids = [
        row[0]
        for row in connection.execute(
            "SELECT id FROM investigations WHERE created_at < ? ORDER BY id", (cutoff,)
        ).fetchall()
    ]
    connection.close()

    for investigation_id in expired_ids:
        _record_evidence_event_if_available(
            investigation_id,
            "retention_expired",
            "retention-policy",
            f"Investigation exceeded the configured {retention_days}-day retention period.",
        )
        purge_source_artifact(
            DB_PATH,
            investigation_id,
            actor="retention-policy",
            reason=f"Configured {retention_days}-day retention period expired.",
        )

    connection = sqlite3.connect(DB_PATH)
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM investigations WHERE created_at < ?", (cutoff,))
        deleted_count = cursor.rowcount
        connection.commit()
    finally:
        connection.close()
    return {
        "success": True,
        "retention_days": retention_days,
        "deleted_count": deleted_count,
        "cutoff": cutoff,
    }


async def _retention_sweep_loop():
    while True:
        try:
            await asyncio.to_thread(run_retention_cleanup)
        except Exception:
            logging.exception("Scheduled privacy retention cleanup failed.")
        await asyncio.sleep(3600)


@app.on_event("startup")
async def start_retention_sweeper():
    app.state.retention_task = asyncio.create_task(_retention_sweep_loop())
    app.state.gmail_monitor_task = asyncio.create_task(gmail_monitor.run())


@app.on_event("shutdown")
async def stop_retention_sweeper():
    for task_name in ("retention_task", "gmail_monitor_task"):
        task = getattr(app.state, task_name, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


def save_investigation(result: dict):
    headers = result.get("headers", {})
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO investigations (
            created_at, sender, recipient, subject,
            threat_score, risk_level, classification,
            origin_ip, result_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        headers.get("from"),
        headers.get("to"),
        headers.get("subject"),
        result.get("threat_score", 0),
        result.get("risk_level"),
        result.get("classification"),
        result.get("candidate_origin_ip"),
        __import__("json").dumps(result, default=str),
    ))
    investigation_id = cursor.lastrowid
    connection.commit()
    connection.close()
    return investigation_id


def update_investigation_result(investigation_id: int, result: dict):
    headers = result.get("headers", {})
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("""
        UPDATE investigations
        SET sender = ?, recipient = ?, subject = ?,
            threat_score = ?, risk_level = ?, classification = ?,
            origin_ip = ?, result_json = ?
        WHERE id = ?
    """, (
        headers.get("from"),
        headers.get("to"),
        headers.get("subject"),
        result.get("threat_score", 0),
        result.get("risk_level"),
        result.get("classification"),
        result.get("candidate_origin_ip"),
        __import__("json").dumps(result, default=str),
        investigation_id,
    ))
    connection.commit()
    connection.close()


init_database()

@app.get("/")
def root():
    return {"message": "MailCipherX-AI backend is running!"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/privacy/settings")
def privacy_settings():
    return get_privacy_settings(DB_PATH)


@app.patch("/privacy/settings")
def update_privacy_settings_endpoint(request: PrivacySettingsUpdate):
    values = request.dict(exclude_unset=True)
    if "retention_days" in values and values["retention_days"] is not None:
        if values["retention_days"] < 0 or values["retention_days"] > 3650:
            raise HTTPException(status_code=400, detail="Retention must be between 0 and 3650 days.")
    settings = update_privacy_settings(DB_PATH, values)
    cleanup = {"deleted_count": 0}
    if settings["retention_days"] > 0:
        cleanup = run_retention_cleanup()
        settings = get_privacy_settings(DB_PATH)
    return {**settings, "cleanup_deleted_count": cleanup["deleted_count"]}


@app.post("/privacy/retention/run")
def execute_retention_cleanup():
    return run_retention_cleanup()


@app.get("/alerts")
def alerts():
    return {"alerts": get_alerts()}


@app.get("/alerts/stream")
def alerts_stream(request: Request, after_id: int = 0):
    try:
        last_id = max(0, int(request.headers.get("last-event-id") or after_id))
    except ValueError:
        last_id = max(0, after_id)

    async def iter_alerts():
        nonlocal last_id
        loop = asyncio.get_running_loop()
        last_heartbeat = loop.time()
        yield "retry: 2000\n\n"
        while not await request.is_disconnected():
            pending = get_alerts_after(last_id)
            for alert in pending:
                last_id = alert["id"]
                yield f"id: {last_id}\ndata: {json.dumps(alert, default=str)}\n\n"
            if not pending and loop.time() - last_heartbeat >= 15:
                yield ": keep-alive\n\n"
                last_heartbeat = loop.time()
            await asyncio.sleep(2)

    return StreamingResponse(
        iter_alerts(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/analyze")
def analyze_email(request: EmailRequest):
    return _analyze_email(request, mask_response=True)


def _analyze_email(
    request: EmailRequest,
    mask_response: bool,
    persist: bool = True,
    allow_external_lookups: bool = True,
    alert_source: str = "email_analysis",
):
    email_text = request.email
    source_type = "submitted_text"
    if request.source_file_base64 is not None:
        try:
            source_content = base64.b64decode(request.source_file_base64, validate=True)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Uploaded source evidence is not valid Base64.")
        if len(source_content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Uploaded source evidence exceeds the 10 MB limit.")
        source_type = "uploaded_eml"
    else:
        source_content = email_text.encode("utf-8")
    source_sha256 = sha256_bytes(source_content)
    analysis_text_sha256 = sha256_bytes(email_text.encode("utf-8"))
    email_lower = email_text.lower()

    headers = {}

    for line in email_text.splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            name = name.strip().lower()

            if name in [
                "from",
                "to",
                "subject",
                "date",
                "return-path",
                "reply-to",
                "received"
            ]:
                headers[name] = value.strip()

    score = 0
    findings = []
    score_breakdown = []
    # Extract URLs from the email
    urls = extract_urls(email_text)
    url_domains = extract_url_domains(urls)

    # Collect domain intelligence for the sender domain and URL domains.
    sender_domain_for_intel = ""
    if headers.get("from", "") and "@" in headers.get("from", ""):
        sender_domain_for_intel = headers.get("from", "").split("@")[-1].replace(">", "").strip().lower()

    intelligence_domains = []
    for domain in [sender_domain_for_intel] + url_domains:
        if domain and domain not in intelligence_domains:
            intelligence_domains.append(domain)

    if allow_external_lookups:
        domain_intelligence = [
            check_domain_intelligence(domain, include_whois=(domain == sender_domain_for_intel))
            for domain in intelligence_domains[:5]
        ]
    else:
        domain_intelligence = [
            {"domain": domain, "status": "not_checked_privacy", "dns": {}, "rdap": {}, "signals": []}
            for domain in intelligence_domains[:5]
        ]

    # Check extracted URLs against VirusTotal
    url_intelligence = []

    for url in urls:
        result = (
            check_virustotal_url(url)
            if allow_external_lookups
            else {"status": "not_checked_privacy", "url": url}
        )
        url_intelligence.append(result)
        # Add VirusTotal URL intelligence to the risk score
    for result in url_intelligence:
        if result.get("status") != "found":
            continue

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)

        if malicious > 0:
            score += min(30, malicious * 5)

            findings.append(
                f"VirusTotal flagged the URL as malicious by {malicious} security engine(s)."
            )

        elif suspicious > 0:
            score += min(15, suspicious * 3)

            findings.append(
                f"VirusTotal flagged the URL as suspicious by {suspicious} security engine(s)."
            )

        else:
            findings.append(
                "VirusTotal found no malicious or suspicious detections for the URL."
            )    

    # PhishTank checks are opt-in, rate-bounded, and cached by exact URL.
    phishtank_intelligence = (
        check_phishtank_urls(urls)
        if allow_external_lookups
        else {
            "source_status": "not_checked_privacy",
            "checks": [{"url": url, "status": "not_checked_privacy"} for url in urls],
        }
    )
    phishtank_by_url = {item["url"]: item for item in phishtank_intelligence["checks"]}
    for result in url_intelligence:
        match = phishtank_by_url.get(result.get("url"), {"status": "not_checked"})
        result["phishtank"] = {key: value for key, value in match.items() if key != "url"}
        if match.get("status") == "found":
            score += 30
            score_breakdown.append({"reason": "Exact URL matched a verified, valid PhishTank report", "points": 30})
            findings.append("PhishTank matched an exact URL as verified and valid phishing.")
    # Get sender and Reply-To
    sender = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
        # Detect DKIM-Signature header
    dkim_result = None

    dkim_header = None

    for line in email_text.splitlines():
        if line.lower().startswith("dkim-signature:"):
            dkim_header = line
            break

    if dkim_header:
        dkim_domain_match = re.search(
            r"\bd=([^;\s]+)",
            dkim_header,
            re.IGNORECASE
        )

        dkim_selector_match = re.search(
            r"\bs=([^;\s]+)",
            dkim_header,
            re.IGNORECASE
        )

        if dkim_domain_match and dkim_selector_match:
            dkim_domain = dkim_domain_match.group(1).strip()
            dkim_selector = dkim_selector_match.group(1).strip()

            dkim_result = check_dkim(
                dkim_domain,
                dkim_selector
            )
            # Check DKIM signing-domain alignment
            if sender and "@" in sender:
                from_domain = sender.split("@")[-1].replace(">", "").strip()

                dkim_aligned = domains_align(
                    from_domain,
                    dkim_domain
                )

                dkim_result["from_domain"] = from_domain
                dkim_result["alignment"] = (
                    "aligned" if dkim_aligned else "not_aligned"
                )

                if dkim_aligned:
                    findings.append(
                        "DKIM signing domain aligns with the visible From domain."
                    )
                else:
                    findings.append(
                        "DKIM signing domain does not align with the visible From domain."
                    )
        else:
            dkim_result = {
                "status": "invalid_header",
                "message": "DKIM-Signature header was found, but domain or selector could not be extracted."
            }
                # Add DKIM result to evidence-based findings
    if dkim_result:
        dkim_status = dkim_result.get("status", "")

        if dkim_status == "key_found":
            findings.append(
                "DKIM public key found. Cryptographic signature verification has not yet been performed."
            )

        elif dkim_status == "key_not_found":
            score += 15
            findings.append(
                "DKIM verification problem: no public key was found for the signing domain and selector."
            )

        elif dkim_status == "invalid_header":
            score += 5
            findings.append(
                "DKIM-Signature header is present but could not be parsed correctly."
            )

        elif dkim_status == "not_present":
            findings.append(
                "No DKIM-Signature header was found."
            )

        elif dkim_status == "error":
            findings.append(
                "DKIM public-key lookup could not be completed."
            )
    else:
        dkim_result = {
            "status": "not_present",
            "message": "No DKIM-Signature header was found."
        }
        # Check DMARC policy
    dmarc_result = None

    if sender and "@" in sender:
        sender_domain = sender.split("@")[-1].replace(">", "").strip()

        dmarc_result = check_dmarc(sender_domain)  
 

    # it is not, by itself, evidence that this email is malicious.
    if dmarc_result:
        dmarc_status = dmarc_result.get("status", "")

        if dmarc_status == "found":
            findings.append(
                "DMARC policy found for the sender domain."
            )

        elif dmarc_status == "not_found":
            findings.append(
                "No DMARC policy was found for the sender domain."
            )

        elif dmarc_status == "error":
            findings.append(
                "DMARC policy lookup could not be completed."
            )
    # Real SPF DNS lookup
    spf_result = None
        # Extract IP addresses from Received headers
    received_headers = []

    for line in email_text.splitlines():
        if line.lower().startswith("received:"):
            received_headers.append(line)

    # Build a forensic relay path
    relay_path = []

    for index, received in enumerate(received_headers, start=1):
        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            received
        )

        hop_details = []

        for ip in found_ips:
            intelligence = (
                lookup_ip(ip)
                if allow_external_lookups
                else {"status": "not_checked_privacy", "ip": ip}
            )

            hop_details.append({
                "ip": ip,
                "country": intelligence.get("country"),
                "region": intelligence.get("region"),
                "city": intelligence.get("city"),
                "isp": intelligence.get("isp"),
                "organization": intelligence.get("organization"),
                "asn": intelligence.get("asn"),
            })

        relay_path.append({
            "hop": index,
            "header": received,
            "ip_addresses": found_ips,
            "intelligence": hop_details,
        })

    ip_addresses = []

    for received in received_headers:
        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            received
        )

        for ip in found_ips:
            if ip not in ip_addresses and is_public_ip(ip):
                ip_addresses.append(ip)

    ip_addresses = []

    for received in received_headers:
        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            received
        )

        for ip in found_ips:
            if ip not in ip_addresses and is_public_ip(ip):
                ip_addresses.append(ip)
    # Identify the oldest public IP as a candidate originating IP.
    # This is a candidate only because Received headers must be
    # interpreted in the context of trusted mail infrastructure.
    candidate_origin_ip = None

    if ip_addresses:
        candidate_origin_ip = ip_addresses[-1]            
    relay_path_analysis = analyze_relay_path(received_headers, relay_path)
    for anomaly in relay_path_analysis["anomalies"]:
        findings.append(
            f"Relay path {anomaly['severity'].lower()} signal: {anomaly['summary']} {anomaly['evidence']}"
        )
    # Look up real information for each extracted IP
    ip_intelligence = []

    for ip in ip_addresses:
        intelligence = (
            lookup_ip(ip)
            if allow_external_lookups
            else {"status": "not_checked_privacy", "ip": ip}
        )

        reputation = (
            check_virustotal_ip(ip)
            if allow_external_lookups
            else {"status": "not_checked_privacy", "malicious": 0, "suspicious": 0}
        )

        intelligence["reputation"] = reputation

        if reputation.get("malicious", 0) > 0:
            intelligence["role"] = "Suspicious Infrastructure"
        else:
            intelligence["role"] = "Relay Server"

        ip_intelligence.append(intelligence)
    # Get intelligence for the candidate originating IP
    candidate_origin_intelligence = None

    if candidate_origin_ip:
        for intelligence in ip_intelligence:
            if intelligence.get("ip") == candidate_origin_ip:
                candidate_origin_intelligence = intelligence
                break
    # Real SPF evaluation using sender domain and sending IP
    spf_result = None

    if return_path and "@" in return_path and ip_addresses:
        envelope_sender = return_path.strip("<> ")
        envelope_domain = envelope_sender.split("@")[-1].strip()
        sending_ip = ip_addresses[0]

        helo_hostname = "unknown"

        if received_headers:
            match = re.search(
                r"from\s+([A-Za-z0-9.-]+)",
                received_headers[0],
                re.IGNORECASE
            )

            if match:
                helo_hostname = match.group(1)

        try:
            result, explanation = spf.check2(
                sending_ip,
                envelope_sender,
                helo_hostname
            )

            spf_result = {
                "status": result,
                "explanation": explanation,
                "envelope_sender": envelope_sender,
                "domain": envelope_domain,
                "sending_ip": sending_ip,
            }

        except Exception as e:
            spf_result = {
                "status": "error",
                "envelope_sender": envelope_sender,
                "domain": envelope_domain,
                "sending_ip": sending_ip,
                "error": str(e),
            }

    elif sender and "@" in sender and ip_addresses:
        spf_result = {
            "status": "not_evaluated",
            "message": "SPF was not evaluated because the SMTP envelope sender (Return-Path) was not available.",
            "sending_ip": ip_addresses[0],
        }
    # Check SPF alignment with the visible From domain
    if spf_result and spf_result.get("domain") and sender and "@" in sender:
        from_domain = sender.split("@")[-1].replace(">", "").strip()
        spf_domain = spf_result.get("domain")

        spf_aligned = domains_align(
            from_domain,
            spf_domain
        )

        spf_result["from_domain"] = from_domain
        spf_result["alignment"] = (
            "aligned" if spf_aligned else "not_aligned"
        )

        if spf_aligned:
            findings.append(
                "SPF domain aligns with the visible From domain."
            )
        else:
            findings.append(
                "SPF domain does not align with the visible From domain."
            )
    # Add SPF result to evidence-based risk score
    if spf_result:
        spf_status = spf_result.get("status", "").lower()

        if spf_status == "fail":
            score += 25
            score_breakdown.append({
                "reason": "SPF failure",
                "points": 25,
            })
            findings.append(
                "SPF failed: the sending IP is not authorized to send email for this domain."
            )

        elif spf_status == "softfail":
            score += 10
            score_breakdown.append({
                "reason": "SPF softfail",
                "points": 10,
            })
            findings.append(
                "SPF softfail: the domain owner discourages this sending host."
            )

        elif spf_status == "neutral":
            findings.append(
                "SPF neutral: the domain does not explicitly authorize or reject this sending host."
            )

        elif spf_status == "none":
            findings.append(
                "SPF record was not available for evaluation."
            )

        elif spf_status == "pass":
            findings.append(
                "SPF passed: the sending IP is authorized for the evaluated domain."
            )

        elif spf_status in ["temperror", "permerror"]:
            findings.append(
                f"SPF evaluation returned {spf_status}."
            )
    # Evaluate DMARC using the completed SPF and DKIM results
    dmarc_evaluation = None

    if sender and "@" in sender:
        from_domain = sender.split("@")[-1].replace(">", "").strip()

        dmarc_evaluation = evaluate_dmarc(
            from_domain,
            spf_result,
            dkim_result
        )

        findings.append(
            f"DMARC evaluation: {dmarc_evaluation['status']}."
        ) 
# 1. Check Reply-To mismatch
    if sender and reply_to:
        sender_domain = sender.split("@")[-1].replace(">", "").strip()
        reply_domain = reply_to.split("@")[-1].replace(">", "").strip()

        if sender_domain.lower() != reply_domain.lower():
            score += 25
            score_breakdown.append({
                "reason": "Reply-To domain mismatch",
                "points": 25,
            })
            findings.append(
                "Reply-To domain differs from the sender domain."
            )

    # 2. Check suspicious urgency phrases
    suspicious_phrases = [
        "urgent",
        "immediately",
        "verify your account",
        "verify your password",
        "account suspended",
        "account locked",
        "click here",
        "confirm your identity",
        "payment required",
        "act now",
    ]

    detected_phrases = []

    for phrase in suspicious_phrases:
        if phrase in email_lower:
            detected_phrases.append(phrase)

    if detected_phrases:
        points = min(len(detected_phrases) * 5, 25)
        score += points

        score_breakdown.append({
            "reason": "Suspicious social-engineering language",
            "points": points,
        })

        findings.append(
            "Suspicious social-engineering language detected: "
            + ", ".join(detected_phrases)
        )
        # Detect credential requests
    credential_phrases = [
        "username and password",
        "username/password",
        "enter your password",
        "provide your password",
        "confirm your password",
        "login credentials",
        "credentials",
        "password",
    ]

    detected_credentials = []

    for phrase in credential_phrases:
        if phrase in email_lower:
            detected_credentials.append(phrase)

    if detected_credentials:
        score += 20

        score_breakdown.append({
            "reason": "Credential request",
            "points": 20,
        })

        findings.append(
            "Credential request detected: "
            + ", ".join(detected_credentials)
        )

    # 3. Report URLs without treating their existence as malicious
    url_count = len(urls)

    if url_count > 0:
        findings.append(
            f"{url_count} URL(s) detected in the email."
        )
    # Detect suspicious login/account URLs
    suspicious_url_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "secure",
        "password",
        "authenticate",
    ]

    suspicious_urls = []

    for url in urls:
        url_lower = url.lower()

        if any(word in url_lower for word in suspicious_url_words):
            suspicious_urls.append(url)

    if suspicious_urls:
        points = min(len(suspicious_urls) * 15, 30)
        score += points

        score_breakdown.append({
            "reason": "Suspicious account/login URL",
            "points": points,
        })

        findings.append(
            "Suspicious account/login URL detected: "
            + ", ".join(suspicious_urls)
        )
    # Detect possible brand impersonation in sender domain
    impersonation_patterns = {
        "microsoft": ["micr0soft", "microsoft-support", "microsoft-login"],
        "google": ["g00gle", "google-security", "google-login"],
        "apple": ["app1e", "apple-support", "apple-login"],
        "paypal": ["paypa1", "paypal-security", "paypal-login"],
        "amazon": ["amaz0n", "amazon-support", "amazon-login"],
    }

    sender_lower = sender.lower()

    for brand, suspicious_domains in impersonation_patterns.items():
        if brand in sender_lower:
            if any(domain in sender_lower for domain in suspicious_domains):
                score += 15

                score_breakdown.append({
                    "reason": f"Possible {brand.title()} sender-domain impersonation",
                    "points": 15,
                })

                findings.append(
                    f"Possible {brand.title()} sender-domain impersonation detected."
                )
                break
    # 4. Check suspicious attachment types
    dangerous_extensions = [
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".msi",
        ".dll",
    ]

    detected_files = [
        extension
        for extension in dangerous_extensions
        if extension in email_lower
    ]

    if detected_files:
        score += 25

        score_breakdown.append({
            "reason": "Potentially dangerous attachment",
            "points": 25,
        })

        findings.append(
            "Potentially dangerous attachment type detected: "
            + ", ".join(detected_files)
        )

    # AI-assisted NLP analysis is kept separate from the existing evidence score
    # so the same language indicators are not double-counted.
    nlp_analysis = analyze_email_nlp(email_text, headers, urls)
    ml_analysis = classify_email_ml(email_text, headers, urls)
    resolve_shorteners = (
        allow_external_lookups
        and os.getenv("ENABLE_SAFE_SHORTENER_RESOLUTION", "false").strip().lower() in {"1", "true", "yes"}
    )
    url_obfuscation_analysis = analyze_obfuscated_urls(
        urls,
        email_text,
        resolve_shorteners=resolve_shorteners,
    )
    bec_analysis = analyze_bec_patterns(
        email_text, headers, url_obfuscation_analysis, urls
    )
    attribution_assessment = build_attribution_assessment(
        DB_PATH,
        headers,
        spf_result,
        dkim_result,
        dmarc_evaluation,
        candidate_origin_ip,
        candidate_origin_intelligence,
        relay_path_analysis,
    )

    for item in url_obfuscation_analysis["urls"]:
        signal_names = ", ".join(signal["type"].replace("_", " ") for signal in item["signals"])
        findings.append(f"URL camouflage indicator ({signal_names}): {item['url']}")
    for signal in url_obfuscation_analysis["link_text_signals"]:
        findings.append(f"URL presentation mismatch: {signal['detail']}")
    for resolution in url_obfuscation_analysis["shortener_resolution"]["results"]:
        destination = resolution.get("destination")
        if destination and destination != resolution.get("url"):
            findings.append(f"Shortened URL redirect destination observed: {destination}")
    for signal in bec_analysis["signals"]:
        findings.append(f"Possible BEC pattern ({signal['type'].replace('_', ' ')}): {signal['detail']}")
    if attribution_assessment.get("status") == "assessment_available":
        findings.append(
            "Sender-domain and origin evidence consistency (not human identity proof): "
            f"{attribution_assessment['confidence_score']}/100 ({attribution_assessment['confidence_label']})."
        )

    score = min(score, 100)

    if score >= 75:
        risk_level = "Critical"
    elif score >= 50:
        risk_level = "High"
    elif score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    # Classify the email based on detected evidence
    classification = "Suspicious"

    has_credential_request = bool(detected_credentials)
    has_suspicious_url = bool(suspicious_urls)

    if has_credential_request and has_suspicious_url:
        classification = "Phishing"
    elif score >= 75:
        classification = "Phishing"
    elif score < 25:
        classification = "Low Risk"

    if ml_analysis.get("classification") in {"phishing", "fraud", "suspicious", "impersonated"}:
        classification = ml_analysis["classification"].title()
    elif ml_analysis.get("classification") == "legitimate":
        classification = "Low Risk"

    if not findings:
        findings.append("No obvious suspicious indicators detected.")

    threat_intelligence = build_threat_intelligence_summary(
        ip_intelligence,
        domain_intelligence,
        url_intelligence,
    )
    if allow_external_lookups:
        infrastructure_intelligence = build_infrastructure_intelligence(ip_intelligence)
    else:
        infrastructure_intelligence = {
            "summary": {
                "ips_checked": 0,
                "tor_exit_ips": 0,
                "vpn_or_proxy_ips": 0,
                "hosting_ips": 0,
                "abuse_reported_ips": 0,
                "botnet_c2_ips": 0,
                "open_relay_ips": 0,
                "abuseipdb_ips_checked": 0,
            },
            "source_status": {
                "ip_api_proxy_hosting": "not_checked_privacy",
                "tor_project_exit_list": "not_checked_privacy",
                "abuseipdb": "not_checked_privacy",
                "botnet_c2_list": "not_checked_privacy",
                "feodo_tracker_botnet_c2": "not_checked_privacy",
                "open_relay_list": "not_checked_privacy",
            },
            "indicators": [],
            "note": "Third-party infrastructure lookups were skipped by the Gmail monitoring privacy setting.",
        }
    threat_intelligence["indicators"].extend(infrastructure_intelligence["indicators"])
    threat_intelligence["infrastructure_summary"] = infrastructure_intelligence["summary"]
    threat_intelligence["infrastructure_source_status"] = infrastructure_intelligence["source_status"]
    threat_intelligence["source_status"].update({
        "virustotal": (
            ("configured" if VIRUSTOTAL_API_KEY else "not_configured")
            if allow_external_lookups else "not_checked_privacy"
        ),
        "abuseipdb": infrastructure_intelligence["source_status"].get("abuseipdb", "unknown"),
        "phishtank": phishtank_intelligence["source_status"],
    })

    result = {
        "message": "Email analyzed successfully.",
        "headers": headers,
        "spf": spf_result,
        "dkim":dkim_result,
        "dmarc":dmarc_result,
        "dmarc_evaluation": dmarc_evaluation,
        "urls": urls, 
        "url_domains": url_domains,
        "domain_intelligence": domain_intelligence,
        "url_intelligence": url_intelligence,
        "threat_intelligence": threat_intelligence,
        "infrastructure_intelligence": infrastructure_intelligence,
        "nlp_analysis": nlp_analysis,
        "ml_classifier": ml_analysis,
        "bec_analysis": bec_analysis,
        "url_obfuscation_analysis": url_obfuscation_analysis,
        "attribution_assessment": attribution_assessment,
        "received_headers": received_headers,
        "relay_path":relay_path,
        "relay_path_analysis": relay_path_analysis,
        "ip_addresses": ip_addresses,
        "candidate_origin_ip":candidate_origin_ip,
        "candidate_origin_intelligence":candidate_origin_intelligence,
        "ip_intelligence": ip_intelligence,
        "threat_score": score,
        "score_breakdown": score_breakdown,
        "risk_level": risk_level,
        "classification": classification,
        "findings": findings,
        "status": "analysis_complete",
    }

    result["recommendations"] = build_recommendations(result)

    if score >= 60 or ml_analysis.get("classification") in {"phishing", "fraud", "suspicious", "impersonated"}:
        alert = push_alert(
            alert_source,
            (
                f"New Gmail message classified as {ml_analysis.get('classification', 'high risk')}"
                if alert_source == "gmail_monitor"
                else f"High-risk {ml_analysis.get('classification', 'email')} threat detected"
            ),
            "high" if score >= 60 else "medium",
            {"score": score, "classification": classification, "risk_level": risk_level},
        )
        result["alert"] = alert

    if persist:
        investigation_id = save_investigation(result)
        result["investigation_id"] = investigation_id

        preserve_source, max_artifact_bytes = _evidence_artifact_settings()
        evidence_entry = append_evidence_event(
            DB_PATH,
            investigation_id,
            "message_received",
            actor="system",
            notes="Source was received for email analysis.",
            source_sha256=source_sha256,
            analysis_text_sha256=analysis_text_sha256,
            byte_length=len(source_content),
            details={"source_type": source_type},
            source_content=source_content,
            preserve_source=preserve_source,
            max_artifact_bytes=max_artifact_bytes,
        )
        artifact_status = evidence_entry["details"]["artifact_status"]
        result["evidence_integrity"] = {
            "source_sha256": source_sha256,
            "analysis_text_sha256": analysis_text_sha256,
            "source_bytes": len(source_content),
            "source_type": source_type,
            "artifact_status": artifact_status,
            "ledger_entry_id": evidence_entry["id"],
            "ledger_record_hash": evidence_entry["record_hash"],
            "ledger_previous_hash": evidence_entry["previous_hash"],
            "note": "The chain is locally hash-linked. Actor labels are not authenticated.",
        }
        findings.append(f"Evidence ledger recorded source SHA-256 {source_sha256}.")
        if artifact_status == "stored":
            findings.append("Original source bytes were preserved for later integrity verification.")
        elif artifact_status == "not_stored_by_configuration":
            findings.append("Only source hashes were preserved; raw evidence storage is disabled.")
        else:
            findings.append("Original source bytes exceeded the configured evidence storage limit and were not retained.")

        # Persist the generated investigation ID inside the stored record as well.
        update_investigation_result(investigation_id, result)
    else:
        result["evidence_integrity"] = {
            "source_sha256": source_sha256,
            "analysis_text_sha256": analysis_text_sha256,
            "source_bytes": len(source_content),
            "source_type": "gmail_monitor_ephemeral",
            "artifact_status": "not_persisted_by_privacy_policy",
            "note": "This mailbox message was analyzed in memory; message content and analysis details were not saved.",
        }

    return _privacy_response(result) if mask_response else result


def _analyze_gmail_message(message_text: str, allow_external_intel: bool):
    return _analyze_email(
        EmailRequest(email=message_text),
        mask_response=False,
        persist=False,
        allow_external_lookups=allow_external_intel,
        alert_source="gmail_monitor",
    )


gmail_monitor = GmailInboxMonitor(
    os.getenv("GMAIL_MONITOR_DB_PATH", DB_PATH),
    _analyze_gmail_message,
)
gmail_monitor.initialize()


@app.get("/gmail-monitor/status")
def gmail_monitor_status():
    return gmail_monitor.public_status()


@app.get("/investigations")
def list_investigations(search: str = "", limit: int = 500):
    limit = max(1, min(limit, 1000))
    search_pattern = f"%{search.strip()}%"
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    rows = connection.execute("""
        SELECT id, created_at, sender, recipient, subject,
               threat_score, risk_level, classification, origin_ip
        FROM investigations
        WHERE ? = '' OR sender LIKE ? OR recipient LIKE ? OR subject LIKE ?
              OR origin_ip LIKE ? OR risk_level LIKE ? OR classification LIKE ?
        ORDER BY id DESC
        LIMIT ?
    """, (search.strip(), search_pattern, search_pattern, search_pattern,
          search_pattern, search_pattern, search_pattern, limit)).fetchall()
    connection.close()
    return {"investigations": _privacy_response([dict(row) for row in rows])}


def _case_record(row):
    record = dict(row)
    record["tags"] = json.loads(record.pop("tags_json", "[]"))
    return record


@app.get("/cases")
def list_cases(search: str = ""):
    search = search.strip()
    pattern = f"%{search}%"
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    rows = connection.execute("""
        SELECT c.*, COUNT(ci.investigation_id) AS investigation_count
        FROM cases c
        LEFT JOIN case_investigations ci ON ci.case_id = c.id
        WHERE ? = '' OR c.title LIKE ? OR c.description LIKE ? OR c.tags_json LIKE ?
        GROUP BY c.id
        ORDER BY c.updated_at DESC, c.id DESC
    """, (search, pattern, pattern, pattern)).fetchall()
    connection.close()
    return {"cases": _privacy_response([_case_record(row) for row in rows])}


@app.post("/cases")
def create_case(request: CaseCreateRequest):
    title = request.title.strip()
    if not title:
        raise HTTPException(status_code=400, detail="Case title is required.")
    tags = list(dict.fromkeys(tag.strip() for tag in (request.tags or []) if tag.strip()))
    now = datetime.now(timezone.utc).isoformat()
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO cases (title, description, tags_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (title, request.description.strip(), json.dumps(tags), now, now),
    )
    case_id = cursor.lastrowid
    connection.commit()
    connection.close()
    return {"success": True, "case_id": case_id}


@app.get("/cases/{case_id}")
def get_case(case_id: int):
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    case = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if case is None:
        connection.close()
        raise HTTPException(status_code=404, detail="Case not found.")
    investigations = connection.execute("""
        SELECT i.id, i.created_at, i.sender, i.recipient, i.subject,
               i.threat_score, i.risk_level, i.classification, i.origin_ip,
               ci.added_at
        FROM case_investigations ci
        JOIN investigations i ON i.id = ci.investigation_id
        WHERE ci.case_id = ?
        ORDER BY i.created_at DESC, i.id DESC
    """, (case_id,)).fetchall()
    connection.close()
    return _privacy_response({"case": _case_record(case), "investigations": [dict(row) for row in investigations]})


@app.patch("/cases/{case_id}")
def update_case(case_id: int, request: CaseUpdateRequest):
    changes = request.dict(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Provide at least one case field to update.")
    if "title" in changes:
        changes["title"] = (changes["title"] or "").strip()
        if not changes["title"]:
            raise HTTPException(status_code=400, detail="Case title cannot be empty.")
    if "description" in changes:
        changes["description"] = (changes["description"] or "").strip()
    if "status" in changes:
        changes["status"] = (changes["status"] or "").lower()
        if changes["status"] not in {"open", "closed"}:
            raise HTTPException(status_code=400, detail="Case status must be open or closed.")
    if "tags" in changes:
        changes["tags_json"] = json.dumps(list(dict.fromkeys(
            tag.strip() for tag in (changes.pop("tags") or []) if tag.strip()
        )))
    assignments = [f"{field} = ?" for field in changes]
    values = list(changes.values())
    assignments.append("updated_at = ?")
    values.append(datetime.now(timezone.utc).isoformat())
    values.append(case_id)
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(f"UPDATE cases SET {', '.join(assignments)} WHERE id = ?", values)
    updated = cursor.rowcount
    connection.commit()
    connection.close()
    if not updated:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"success": True, "case_id": case_id}


@app.put("/cases/{case_id}/investigations/{investigation_id}")
def add_investigation_to_case(case_id: int, investigation_id: int):
    now = datetime.now(timezone.utc).isoformat()
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    case_exists = cursor.execute("SELECT 1 FROM cases WHERE id = ?", (case_id,)).fetchone()
    investigation_exists = cursor.execute(
        "SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)
    ).fetchone()
    if case_exists is None or investigation_exists is None:
        connection.close()
        raise HTTPException(status_code=404, detail="Case or investigation not found.")
    cursor.execute(
        "INSERT OR IGNORE INTO case_investigations (case_id, investigation_id, added_at) VALUES (?, ?, ?)",
        (case_id, investigation_id, now),
    )
    cursor.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    connection.commit()
    connection.close()
    return {"success": True, "case_id": case_id, "investigation_id": investigation_id}


@app.delete("/cases/{case_id}/investigations/{investigation_id}")
def remove_investigation_from_case(case_id: int, investigation_id: int):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(
        "DELETE FROM case_investigations WHERE case_id = ? AND investigation_id = ?",
        (case_id, investigation_id),
    )
    removed = cursor.rowcount
    if removed:
        cursor.execute(
            "UPDATE cases SET updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), case_id),
        )
    connection.commit()
    connection.close()
    if not removed:
        raise HTTPException(status_code=404, detail="Case membership not found.")
    return {"success": True, "case_id": case_id, "investigation_id": investigation_id}


@app.delete("/cases/{case_id}")
def delete_case(case_id: int):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM case_investigations WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    deleted = cursor.rowcount
    connection.commit()
    connection.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"success": True, "case_id": case_id}


@app.get("/investigations/graph")
def investigation_relationship_graph(limit: int = 300):
    """Return cross-investigation email infrastructure relationships."""
    limit = max(1, min(limit, 1000))
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT id, sender, recipient, origin_ip, risk_level, classification, result_json "
        "FROM investigations ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    connection.close()

    return _privacy_response(build_investigation_relationship_graph([dict(row) for row in rows]))


@app.delete("/investigations/{investigation_id}")
def delete_investigation(investigation_id: int):
    purge_source_artifact(
        DB_PATH,
        investigation_id,
        actor="system",
        reason="Investigation deleted; preserved source artifact purged.",
    )
    _record_evidence_event_if_available(
        investigation_id,
        "investigation_deleted",
        "system",
        "Investigation record was deleted from the active history.",
    )
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM investigations WHERE id = ?",
        (investigation_id,),
    )

    deleted = cursor.rowcount
    connection.commit()
    connection.close()

    if deleted == 0:
        return {
            "success": False,
            "message": "Investigation not found.",
            "investigation_id": investigation_id,
        }

    return {
        "success": True,
        "message": "Investigation deleted successfully.",
        "investigation_id": investigation_id,
    }


@app.delete("/investigations")
def clear_investigations():
    connection = sqlite3.connect(DB_PATH)
    investigation_ids = [row[0] for row in connection.execute("SELECT id FROM investigations").fetchall()]
    connection.close()
    for investigation_id in investigation_ids:
        purge_source_artifact(
            DB_PATH,
            investigation_id,
            actor="system",
            reason="All investigations cleared; preserved source artifact purged.",
        )
        _record_evidence_event_if_available(
            investigation_id,
            "investigation_deleted",
            "system",
            "Investigation record was removed by the clear-history action.",
        )

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("DELETE FROM investigations")
    deleted_count = cursor.rowcount

    # Reset SQLite's AUTOINCREMENT sequence after clearing test data.
    cursor.execute(
        "DELETE FROM sqlite_sequence WHERE name = 'investigations'"
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "message": "All investigations cleared successfully.",
        "deleted_count": deleted_count,
    }


@app.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: int):
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM investigations WHERE id = ?",
        (investigation_id,),
    ).fetchone()
    connection.close()

    if row is None:
        return {"error": "Investigation not found."}

    result = dict(row)
    result["result"] = __import__("json").loads(result.pop("result_json"))
    if not result["result"].get("recommendations"):
        result["result"]["recommendations"] = build_recommendations(result["result"])
    return _privacy_response(result)


@app.get("/investigations/{investigation_id}/evidence")
def get_investigation_evidence(investigation_id: int):
    bundle = get_evidence_bundle(DB_PATH, investigation_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="No evidence ledger exists for this investigation.")
    return _privacy_response(bundle)


@app.post("/investigations/{investigation_id}/evidence/events")
def record_investigation_evidence_event(investigation_id: int, request: EvidenceEventRequest):
    allowed_events = {"reviewed", "transferred", "custody_note"}
    event_type = request.event_type.strip().lower()
    actor = request.actor.strip()
    notes = request.notes.strip()
    if event_type not in allowed_events:
        raise HTTPException(status_code=400, detail="Event type must be reviewed, transferred, or custody_note.")
    if not actor or len(actor) > 120:
        raise HTTPException(status_code=400, detail="Actor label must contain 1 to 120 characters.")
    if len(notes) > 2000:
        raise HTTPException(status_code=400, detail="Event notes cannot exceed 2000 characters.")
    connection = sqlite3.connect(DB_PATH)
    exists = connection.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    connection.close()
    if exists is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    try:
        entry = append_evidence_event(
            DB_PATH,
            investigation_id,
            event_type,
            actor=actor,
            notes=notes,
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    return _privacy_response({"success": True, "event": entry})


@app.get("/investigations/{investigation_id}/evidence/source")
def download_investigation_source(investigation_id: int):
    content, status = get_verified_source_artifact(DB_PATH, investigation_id)
    if status in {"integrity_mismatch", "ledger_integrity_mismatch"}:
        raise HTTPException(status_code=409, detail="Evidence integrity verification failed; source download is disabled.")
    if content is None:
        raise HTTPException(status_code=404, detail="Verified source artifact is unavailable or was purged.")
    try:
        append_evidence_event(
            DB_PATH,
            investigation_id,
            "source_downloaded",
            actor="system",
            notes="Preserved source message downloaded through the evidence endpoint.",
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    bundle = get_evidence_bundle(DB_PATH, investigation_id)
    digest = bundle["source"]["sha256"] if bundle else ""
    return Response(
        content=content,
        media_type="message/rfc822",
        headers={
            "Content-Disposition": f'attachment; filename="investigation-{investigation_id}.eml"',
            "X-Content-SHA256": digest,
        },
    )


@app.get("/api/ip-intelligence/{ip}")
def api_ip_intelligence(ip: str):
    """Return geolocation and optional reputation intelligence for one public IP."""
    if not is_public_ip(ip):
        return _privacy_response({
            "status": "invalid",
            "ip": ip,
            "message": "Only public IPv4/IPv6 addresses are supported.",
        })

    intelligence = lookup_ip(ip)
    reputation = check_virustotal_ip(ip)
    intelligence["reputation"] = reputation

    malicious = int(reputation.get("malicious") or 0)
    suspicious = int(reputation.get("suspicious") or 0)
    if malicious > 0:
        intelligence["threat_status"] = "High"
    elif suspicious > 0:
        intelligence["threat_status"] = "Medium"
    else:
        intelligence["threat_status"] = "No Known Threat"

    return _privacy_response(intelligence)


@app.get("/api/domain-intelligence/{domain}")
def api_domain_intelligence(domain: str):
    """Return passive DNS, RDAP, WHOIS, and hosting fingerprints for one domain."""
    return _privacy_response(check_domain_intelligence(domain, include_whois=True))


@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
        "service": "MailCipherX-AI API",
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
    }



def build_recommendations(result: dict):
    """Build evidence-driven investigator actions from the stored analysis."""
    recommendations = []
    score = int(result.get("threat_score") or 0)
    classification = str(result.get("classification") or "").lower()
    findings = result.get("findings") or []
    attachments = result.get("attachments") or []
    urls = result.get("urls") or []
    url_intel = result.get("url_intelligence") or []
    threat_intel = result.get("threat_intelligence") or {}
    dmarc_eval = result.get("dmarc_evaluation") or {}
    spf_result = result.get("spf") or {}
    dkim_result = result.get("dkim") or {}

    if score >= 75 or "phishing" in classification or "malicious" in classification:
        recommendations.append({
            "priority": "High",
            "action": "Quarantine the email and prevent further delivery or user interaction.",
            "reason": "The investigation is classified as phishing/malicious or has a critical threat score."
        })

    critical_attachments = [a for a in attachments if str(a.get("risk", "")).lower() in {"high", "critical"}]
    if critical_attachments:
        names = ", ".join(str(a.get("filename") or "unnamed") for a in critical_attachments)
        recommendations.append({
            "priority": "High",
            "action": f"Do not open or execute the flagged attachment(s): {names}.",
            "reason": "Attachment intelligence identified a high-risk executable/script or suspicious attachment."
        })

    malicious_urls = sum(1 for item in url_intel if int(item.get("malicious") or 0) > 0)
    suspicious_urls = sum(1 for item in url_intel if int(item.get("suspicious") or 0) > 0)
    if malicious_urls > 0:
        recommendations.append({
            "priority": "High",
            "action": "Block the malicious URL indicators and investigate affected users or sessions.",
            "reason": f"Threat intelligence reported {malicious_urls} malicious URL indicator(s)."
        })
    elif suspicious_urls > 0 or urls:
        recommendations.append({
            "priority": "Medium",
            "action": "Review detected URLs and avoid visiting them until reputation and destination checks are complete.",
            "reason": "The email contains URL indicators that require contextual investigation."
        })

    malicious_ips = int((threat_intel.get("summary") or {}).get("malicious_ips") or 0)
    suspicious_ips = int((threat_intel.get("summary") or {}).get("suspicious_ips") or 0)
    if malicious_ips > 0:
        recommendations.append({
            "priority": "High",
            "action": "Investigate and consider blocking the malicious IP infrastructure identified by threat intelligence.",
            "reason": f"Threat intelligence reported {malicious_ips} malicious IP indicator(s)."
        })
    elif suspicious_ips > 0:
        recommendations.append({
            "priority": "Medium",
            "action": "Review the suspicious IP infrastructure and correlate it with trusted mail infrastructure.",
            "reason": f"Threat intelligence reported {suspicious_ips} suspicious IP indicator(s)."
        })

    if str(dmarc_eval.get("status", "")).lower() == "fail" or str(spf_result.get("status", "")).lower() in {"fail", "softfail", "permerror"} or str(dkim_result.get("status", "")).lower() in {"key_not_found", "invalid_header", "error"}:
        recommendations.append({
            "priority": "Medium",
            "action": "Review SPF, DKIM and DMARC failures and validate the sender against trusted organizational mail infrastructure.",
            "reason": "One or more email authentication checks did not establish trustworthy authentication."
        })

    if not result.get("candidate_origin_ip") and not result.get("relay_path"):
        recommendations.append({
            "priority": "Informational",
            "action": "Preserve the original email headers if deeper infrastructure tracing is required.",
            "reason": "No usable Received-header origin or relay path was available in the supplied message."
        })

    recommendations.append({
        "priority": "Informational",
        "action": "Preserve the original email, analysis evidence and forensic report for investigation records.",
        "reason": "Evidence should remain available for correlation, review and incident documentation."
    })

    return recommendations


def _clean_report_string(value):
    """Normalize plain text before it is placed into a ReportLab Paragraph."""
    value = str(value)

    # Remove escape characters that commonly arrive from serialized Markdown/text.
    value = value.replace("\\", "")

    # Convert Markdown links to their visible label.  This deliberately handles
    # any destination so URLs never appear as [label](destination) in the PDF.
    previous = None
    while previous != value:
        previous = value
        value = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', value)

    # Remove Markdown emphasis markers.
    value = value.replace("**", "").replace("__", "")
    return value


def _report_text(value):
    """Convert report values into readable, human-friendly text."""
    if value is None or value == "":
        return "Not available"

    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            label = str(key).replace("_", " ").title()
            parts.append(
                f"<b>{escape(label)}:</b> {_report_text(item)}"
            )
        return "<br/>".join(parts)

    if isinstance(value, list):
        if not value:
            return "None"

        items = []
        for item in value:
            # Support rows accidentally supplied as (field, value) tuples.
            if isinstance(item, tuple) and len(item) == 2:
                items.append(
                    f"<b>{escape(str(item[0]))}:</b> {_report_text(item[1])}"
                )
            elif isinstance(item, (dict, list, tuple)):
                items.append(f"• {_report_text(item)}")
            else:
                items.append(f"• {escape(_clean_report_string(item))}")
        return "<br/>".join(items)

    if isinstance(value, tuple):
        if len(value) == 2:
            return (
                f"<b>{escape(str(value[0]))}:</b> "
                f"{_report_text(value[1])}"
            )
        return " • ".join(_report_text(item) for item in value)

    return escape(_clean_report_string(value))


def _add_report_section(story, title, rows, styles):
    """Add a clean two-column forensic report section."""
    story.append(Paragraph(escape(title), styles["Heading2"]))

    table_data = [[
        Paragraph("Field", styles["TableHeader"]),
        Paragraph("Value", styles["TableHeader"]),
    ]]

    for field, value in rows:
        table_data.append([
            Paragraph(escape(str(field)), styles["BodySmallBold"]),
            Paragraph(_report_text(value), styles["BodySmall"]),
        ])

    table = Table(
        table_data,
        colWidths=[48 * mm, 132 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F1F5F9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(table)
    story.append(Spacer(1, 8))


def _format_authentication(result):
    """Create concise human-readable authentication rows."""
    spf_result = result.get("spf") or {}
    dkim_result = result.get("dkim") or {}
    dmarc_policy = result.get("dmarc") or {}
    dmarc_eval = result.get("dmarc_evaluation") or {}

    return [
        ("SPF Status", spf_result.get("status", "Not available")),
        ("SPF Domain", spf_result.get("domain", "Not available")),
        ("SPF Sending IP", spf_result.get("sending_ip", "Not available")),
        ("SPF Alignment", spf_result.get("alignment", "Not available")),
        ("SPF Explanation", spf_result.get("explanation") or spf_result.get("message") or "No additional explanation available."),
        ("DKIM Status", dkim_result.get("status", "Not available")),
        ("DKIM Domain", dkim_result.get("domain", "Not available")),
        ("DKIM Selector", dkim_result.get("selector", "Not available")),
        ("DKIM Alignment", dkim_result.get("alignment", "Not available")),
        ("DKIM Message", dkim_result.get("message", "Not available")),
        ("DMARC Policy Status", dmarc_policy.get("status", "Not available")),
        ("DMARC Domain", dmarc_policy.get("domain", "Not available")),
        ("DMARC Policy", dmarc_policy.get("record", "Not available")),
        ("DMARC Evaluation", dmarc_eval.get("status", "Not available")),
        ("DMARC Evaluation Reason", dmarc_eval.get("reason", "Not available")),
    ]


def _format_ip_intelligence(ips):
    rows = []
    if not ips:
        return [("IP Intelligence", "No IP intelligence available.")]

    for index, item in enumerate(ips, start=1):
        ip = item.get("ip") or "Unknown"
        status = item.get("status") or "Unknown"
        location = ", ".join(
            str(value)
            for value in [item.get("city"), item.get("region"), item.get("country")]
            if value
        ) or "Unavailable"

        rows.extend([
            (f"IP {index}", ip),
            (f"IP {index} Status", status),
            (f"IP {index} Location", location),
            (f"IP {index} ISP", item.get("isp") or "Unavailable"),
            (f"IP {index} Organization", item.get("organization") or "Unavailable"),
            (f"IP {index} ASN", item.get("asn") or "Unavailable"),
        ])

        reputation = item.get("reputation") or {}
        if reputation:
            rows.append((f"IP {index} Reputation", reputation.get("status") or "Unavailable"))
            if reputation.get("malicious") is not None:
                rows.append((f"IP {index} Malicious Detections", reputation.get("malicious", 0)))
            if reputation.get("suspicious") is not None:
                rows.append((f"IP {index} Suspicious Detections", reputation.get("suspicious", 0)))
            if reputation.get("message") or reputation.get("error"):
                rows.append((f"IP {index} Intelligence Note", "External reputation lookup was unavailable."))

    return rows


def _format_domain_intelligence(domains):
    rows = []
    if not domains:
        return [("Domain Intelligence", "No domain intelligence available.")]

    for index, item in enumerate(domains, start=1):
        domain = item.get("domain") or "Unknown"
        rows.append((f"Domain {index}", domain))

        rdap = item.get("rdap") or {}
        rows.append((f"Domain {index} RDAP", rdap.get("status") or "Unavailable"))

        for label, key in [("Registrar", "registrar"), ("Created", "created"),
                           ("Updated", "updated"), ("Expires", "expires")]:
            if rdap.get(key):
                rows.append((f"Domain {index} {label}", rdap.get(key)))

        whois = item.get("whois") or {}
        if whois:
            rows.append((f"Domain {index} WHOIS Status", whois.get("status") or "Unavailable"))
            rows.append((f"Domain {index} WHOIS Server", whois.get("server") or "Unavailable"))
            for label, key in [("WHOIS Registrar", "registrar"), ("WHOIS Created", "created"),
                               ("WHOIS Updated", "updated"), ("WHOIS Expires", "expires")]:
                if whois.get(key):
                    rows.append((f"Domain {index} {label}", whois.get(key)))

        hosting = item.get("hosting_fingerprint") or {}
        if hosting:
            rows.append((f"Domain {index} Hosting Fingerprints", hosting.get("observations") or hosting.get("status")))
            rows.append((f"Domain {index} Hosting Note", hosting.get("note")))

        dns = item.get("dns") or {}
        dns_records = []
        for record_type in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
            values = dns.get(record_type) or []
            if values:
                dns_records.append(f"{record_type}: {', '.join(map(str, values))}")

        rows.append((
            f"Domain {index} DNS",
            "<br/>".join(escape(item) for item in dns_records)
            if dns_records else "No common DNS records returned."
        ))

        signals = item.get("signals") or []
        if signals:
            rows.append((f"Domain {index} Signals", signals))

        if rdap.get("status") == "error" or rdap.get("message"):
            rows.append((
                f"Domain {index} RDAP Note",
                "External RDAP lookup was unavailable in this analysis environment."
            ))

    return rows


def _format_url_intelligence(urls):
    rows = []
    if not urls:
        return [("URL Intelligence", "No URL intelligence available.")]

    for index, item in enumerate(urls, start=1):
        rows.append((f"URL {index}", item.get("url") or "Unknown"))
        rows.append((f"URL {index} Status", item.get("status") or "Unavailable"))

        if item.get("malicious") is not None:
            rows.append((f"URL {index} Malicious Detections", item.get("malicious", 0)))
        if item.get("suspicious") is not None:
            rows.append((f"URL {index} Suspicious Detections", item.get("suspicious", 0)))
        if item.get("reputation") is not None:
            rows.append((f"URL {index} Reputation", item.get("reputation")))

        if item.get("status") == "error":
            rows.append((
                f"URL {index} Intelligence Note",
                "External URL reputation lookup was unavailable in this analysis environment."
            ))
        elif item.get("message"):
            rows.append((f"URL {index} Note", item.get("message")))

    return rows


def _format_relay_path(relay_path):
    """Render Received headers as readable hop-by-hop evidence."""
    rows = []
    if not relay_path:
        return [("SMTP Relay Path", "No Received-header relay path was available.")]

    for hop in relay_path:
        hop_number = hop.get("hop", "?")
        header = hop.get("header") or "Not available"
        ips = hop.get("ip_addresses") or []
        intelligence = hop.get("intelligence") or []

        rows.append((f"Hop {hop_number} Header", header))
        rows.append((f"Hop {hop_number} IP Addresses", ips or "No IP addresses extracted"))

        clues = []
        for item in intelligence:
            ip = item.get("ip") or "Unknown"
            location = ", ".join(
                str(value)
                for value in [item.get("city"), item.get("region"), item.get("country")]
                if value
            ) or "Location unavailable"
            clues.append(f"{ip}: {location}")

        if clues:
            rows.append((f"Hop {hop_number} Location Clues", clues))

    return rows


def _format_threat_intelligence(threat_intel):
    summary = threat_intel.get("summary") or {}
    overall = threat_intel.get("overall_status", "No Data")

    if overall == "Informational":
        overall = "Limited / No External Verdict"

    return [
        ("Threat Intelligence Status", overall),
        ("IPs Checked", summary.get("ips_checked", 0)),
        ("Malicious IPs", summary.get("malicious_ips", 0)),
        ("Suspicious IPs", summary.get("suspicious_ips", 0)),
        ("URLs Checked", summary.get("urls_checked", 0)),
        ("Malicious URLs", summary.get("malicious_urls", 0)),
        ("Suspicious URLs", summary.get("suspicious_urls", 0)),
        ("Domains Checked", summary.get("domains_checked", 0)),
        ("Indicators", threat_intel.get("indicators") or "None"),
        ("Intelligence Note", threat_intel.get(
            "note",
            "External intelligence is evidence and does not by itself prove sender identity."
        )),
    ]


@app.get("/investigations/{investigation_id}/report")
def generate_investigation_report(investigation_id: int):
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM investigations WHERE id = ?",
        (investigation_id,),
    ).fetchone()
    connection.close()

    if row is None:
        return {"error": "Investigation not found."}

    import json

    stored = dict(row)

    try:
        result = json.loads(stored.get("result_json") or "{}")
    except Exception:
        result = {}
    privacy_settings = get_privacy_settings(DB_PATH)
    stored = mask_sensitive_data(stored, privacy_settings)
    result = mask_sensitive_data(result, privacy_settings)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
    name="TableHeader",
    parent=styles["BodyText"],
    fontName="Helvetica-Bold",
    fontSize=8,
    leading=10,
))

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=24,
        spaceAfter=8,
        textColor=colors.HexColor("#0F172A"),
    ))

    styles.add(ParagraphStyle(
        name="Verdict",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.white,
        spaceAfter=4,
    ))

    styles.add(ParagraphStyle(
        name="VerdictSub",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.white,
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#475569"),
        spaceAfter=16,
    ))

    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#334155"),
    ))

    styles.add(ParagraphStyle(
        name="BodySmallBold",
        parent=styles["BodyText"],
        fontSize=8.5,
        leading=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0F172A"),
    ))

    styles.add(ParagraphStyle(
        name="SectionNote",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=7,
    ))

    styles["Heading2"].spaceBefore = 9
    styles["Heading2"].spaceAfter = 7
    styles["Heading2"].textColor = colors.HexColor("#0F172A")

    score = result.get("threat_score", stored.get("threat_score", 0))
    risk = result.get("risk_level", stored.get("risk_level", "Unknown"))
    classification = result.get("classification", stored.get("classification", "Unknown"))

    headers = result.get("headers", {}) or {}
    findings = result.get("findings", []) or []
    breakdown = result.get("score_breakdown", []) or []
    threat_intel = result.get("threat_intelligence", {}) or {}
    recommendations = result.get("recommendations") or build_recommendations(result)
    attachments = result.get("attachments", []) or []
    domains = result.get("domain_intelligence", []) or []
    urls = result.get("url_intelligence", []) or []
    ips = result.get("ip_intelligence", []) or []
    relay_path = result.get("relay_path", []) or []

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"MailCipherX-AI Investigation #{investigation_id}",
        author="MailCipherX-AI",
    )

    story = [
        Paragraph("MAILCIPHERX-AI", styles["ReportTitle"]),
        Paragraph(
            "Email Threat Detection & Forensics Intelligence Report",
            styles["ReportSubtitle"],
        ),
    ]

    assessment = (
        f"The investigation is classified as {classification} with a threat score "
        f"of {score}/100 and a {risk} risk level. "
        "The score is an evidence-based investigative signal and is not a probability "
        "of maliciousness."
    )

    verdict_text = (
        f"VERDICT: {escape(_clean_report_string(classification).upper())}"
        f"  •  {escape(_clean_report_string(score))}/100"
    )
    verdict = Table([[
        Paragraph(
            verdict_text + "<br/><font size=9>Risk Level: "
            + escape(_clean_report_string(risk).upper()) + "</font>",
            styles["Verdict"],
        )
    ]], colWidths=[170 * mm], hAlign="CENTER")
    verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#7F1D1D") if str(risk).lower() == "critical" else colors.HexColor("#92400E")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#991B1B")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.extend([verdict, Spacer(1, 10)])

    _add_report_section(story, "Executive Summary", [
        ("Investigation ID", f"#{investigation_id}"),
        ("Created", stored.get("created_at")),
        ("Classification", classification),
        ("Threat Score", f"{score}/100"),
        ("Risk Level", risk),
        ("Assessment", assessment),
    ], styles)

    _add_report_section(story, "Email Details", [
        ("From", headers.get("from") or stored.get("sender")),
        ("To", headers.get("to") or stored.get("recipient")),
        ("Subject", headers.get("subject") or stored.get("subject")),
        ("Date", headers.get("date")),
        ("Reply-To", headers.get("reply-to")),
        ("Return-Path", headers.get("return-path")),
    ], styles)

    nlp_analysis = result.get("nlp_analysis") or {}
    nlp_rows = [
        ("Engine", nlp_analysis.get("engine")),
        ("Assessment", nlp_analysis.get("assessment")),
        ("NLP Signal Score", f"{nlp_analysis.get('signal_score', 0)}/100"),
        ("Primary Threat", nlp_analysis.get("primary_threat")),
        ("Detected Categories", nlp_analysis.get("categories") or "None"),
        ("Brand Context", nlp_analysis.get("brand_context") or "None"),
        ("Reply-To Domain Mismatch", "Yes" if nlp_analysis.get("reply_to_domain_mismatch") else "No"),
        ("Suspicious URL Context", nlp_analysis.get("suspicious_url_context") or "None"),
        ("Analysis Note", nlp_analysis.get("note")),
    ]
    _add_report_section(story, "AI-Assisted NLP Analysis", nlp_rows, styles)

    attribution = result.get("attribution_assessment") or {}
    if attribution:
        _add_report_section(story, "Sender and Origin Evidence Consistency", [
            ("Confidence Score", f"{attribution.get('confidence_score', 0)}/100 ({attribution.get('confidence_label', 'Low')})"),
            ("Candidate Sender Domain", attribution.get("candidate_sender_domain")),
            ("Candidate Origin IP", attribution.get("candidate_origin_ip")),
            ("Supporting and Conflicting Signals", attribution.get("signals") or []),
            ("Related Investigations", attribution.get("correlated_investigations") or []),
            ("Scope Note", attribution.get("note")),
        ], styles)

    _add_report_section(
        story,
        "Authentication",
        _format_authentication(result),
        styles,
    )

    _add_report_section(story, "Forensic Infrastructure", [
        ("Candidate Origin IP", result.get("candidate_origin_ip")),
        ("Detected IP Addresses", result.get("ip_addresses") or []),
        ("SMTP Relay Path", _format_relay_path(relay_path)),
    ], styles)

    if result.get("candidate_origin_intelligence"):
        candidate = result.get("candidate_origin_intelligence") or {}
        _add_report_section(story, "Candidate Origin Intelligence", [
            ("IP", candidate.get("ip")),
            ("Status", candidate.get("status")),
            ("Country", candidate.get("country")),
            ("Region", candidate.get("region")),
            ("City", candidate.get("city")),
            ("ISP", candidate.get("isp")),
            ("Organization", candidate.get("organization")),
            ("ASN", candidate.get("asn")),
            ("Role", candidate.get("role")),
        ], styles)

    _add_report_section(
        story,
        "Threat Intelligence Summary",
        _format_threat_intelligence(threat_intel),
        styles,
    )

    _add_report_section(
        story,
        "IP Intelligence",
        _format_ip_intelligence(ips),
        styles,
    )

    _add_report_section(
        story,
        "URL Intelligence",
        _format_url_intelligence(urls),
        styles,
    )

    _add_report_section(
        story,
        "Domain Intelligence",
        _format_domain_intelligence(domains),
        styles,
    )

    if breakdown:
        breakdown_rows = []
        for item in breakdown:
            breakdown_rows.append((
                item.get("reason", "Evidence"),
                f"+{item.get('points', 0)}",
            ))

        breakdown_rows.append(("Total Score", f"{score}/100"))
        _add_report_section(story, "Score Breakdown", breakdown_rows, styles)
    else:
        _add_report_section(
            story,
            "Score Breakdown",
            [("Total Score", f"{score}/100"), ("Evidence", "No score breakdown available.")],
            styles,
        )

    finding_rows = []
    for index, finding in enumerate(findings, start=1):
        finding_rows.append((f"Finding {index}", finding))

    if not finding_rows:
        finding_rows.append(("Findings", "No obvious suspicious indicators were recorded."))

    _add_report_section(story, "Security Findings", finding_rows, styles)

    evidence_integrity = result.get("evidence_integrity") or {}
    if evidence_integrity:
        _add_report_section(story, "Evidence Integrity", [
            ("Source SHA-256", evidence_integrity.get("source_sha256")),
            ("Analyzed Text SHA-256", evidence_integrity.get("analysis_text_sha256")),
            ("Source Bytes", evidence_integrity.get("source_bytes")),
            ("Artifact Status", evidence_integrity.get("artifact_status")),
            ("Ledger Record Hash", evidence_integrity.get("ledger_record_hash")),
        ], styles)

    recommendation_rows = []
    for index, item in enumerate(recommendations, start=1):
        priority = item.get("priority", "Informational")
        action = item.get("action", "Review evidence.")
        reason = item.get("reason", "No additional reason provided.")

        recommendation_rows.append((
            f"Action {index} — {priority}",
            {
                "Action": _clean_report_string(action),
                "Reason": _clean_report_string(reason),
            },
        ))

    _add_report_section(story, "Recommended Actions", recommendation_rows, styles)

    attachment_rows = [
        ("Attachment Count", len(attachments)),
    ]

    if attachments:
        for index, attachment in enumerate(attachments, start=1):
            attachment_rows.extend([
                (f"Attachment {index}", attachment.get("filename") or "Unnamed"),
                (f"Attachment {index} Type", attachment.get("content_type") or "Unknown"),
                (f"Attachment {index} Size", f"{attachment.get('size', 0)} bytes"),
                (f"Attachment {index} Risk", attachment.get("risk") or "Unknown"),
                (f"Attachment {index} Signals", attachment.get("signals") or "None"),
                (f"Attachment {index} Analysis", attachment.get("analysis") or "Metadata-only analysis."),
            ])
    else:
        attachment_rows.append(("Attachment Intelligence", "No attachments detected."))

    _add_report_section(story, "Attachments", attachment_rows, styles)

    detected_urls = result.get("urls") or []
    url_domains = result.get("url_domains") or []

    _add_report_section(story, "URLs & Domains", [
        ("Detected URLs", detected_urls),
        ("URL Domains", url_domains),
    ], styles)

    story.append(Spacer(1, 8))
    story.append(Paragraph("Forensic Limitations", styles["Heading2"]))
    story.append(Paragraph(
        "• IP geolocation is approximate and does not prove the sender's identity or exact physical location.<br/>"
        "• Received headers should be interpreted in the context of trusted mail infrastructure.<br/>"
        "• Candidate origin IPs are investigative clues, not proof of sender identity.<br/>"
        "• External threat-intelligence or RDAP lookup failures indicate unavailable intelligence, not a clean result.<br/>"
        "• MailCipherX-AI does not execute uploaded attachments during metadata analysis.",
        styles["BodySmall"],
    ))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Generated by MailCipherX-AI — Evidence-based email threat detection and forensic intelligence.",
        styles["SectionNote"],
    ))

    def _report_page(canvas, doc):
        canvas.saveState()
        width, _ = A4
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.setLineWidth(0.4)
        canvas.line(15 * mm, 11 * mm, width - 15 * mm, 11 * mm)
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(15 * mm, 6.5 * mm, "MAILCIPHERX-AI  •  CONFIDENTIAL")
        canvas.drawRightString(
            width - 15 * mm,
            6.5 * mm,
            f"Investigation #{investigation_id}  •  Page {doc.page}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_report_page, onLaterPages=_report_page)
    buffer.seek(0)

    if get_evidence_bundle(DB_PATH, investigation_id):
        append_evidence_event(
            DB_PATH,
            investigation_id,
            "report_generated",
            actor="system",
            notes="Forensic PDF report was generated.",
        )

    filename = f"mailcipherx_ai_investigation_{investigation_id}.pdf"

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@app.post("/upload")
async def upload_email(file: UploadFile = File(...)):
    if not file.filename:
        return {"error": "No file selected."}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    if not file.filename.lower().endswith(".eml"):
        return {"error": "Only .eml files are supported."}

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        return {
            "error": "The uploaded email file is too large.",
            "max_size_mb": 10,
        }
    if not content:
        return {"error": "The uploaded file is empty."}

    try:
        parsed_email = BytesParser(policy=policy.default).parsebytes(content)
        email_text = parsed_email.as_string()
        attachments = []

        for part in parsed_email.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                content_type = part.get_content_type()
                size = len(part.get_payload(decode=True) or b"")

                attachment = analyze_attachment_metadata(
                    filename,
                    content_type,
                    size,
                )
                attachments.append(attachment)
    except Exception as e:
        return {
            "error": "The uploaded file could not be parsed as a valid email.",
            "details": str(e),
        }

    result = _analyze_email(EmailRequest(
        email=email_text,
        source_file_base64=base64.b64encode(content).decode("ascii"),
    ), mask_response=False)

    result["attachments"] = attachments

    # Apply attachment intelligence to the investigation score.
    # analyze_email may already have added a generic attachment-extension signal
    # from the serialized .eml text, so avoid double-counting the same evidence.
    for attachment in attachments:
        attachment_points = attachment.get("risk_points", 0)
        attachment_risk = attachment.get("risk", "Low")
        attachment_filename = attachment.get("filename") or "unnamed"

        if attachment_points > 0:
            already_scored = any(
                item.get("reason") in {
                    "Potentially dangerous attachment",
                    "Suspicious attachment",
                }
                for item in result.get("score_breakdown", [])
            )

            if not already_scored:
                result["threat_score"] = min(
                    result["threat_score"] + attachment_points,
                    100,
                )
                result["score_breakdown"].append({
                    "reason": "Attachment intelligence",
                    "points": attachment_points,
                })

            if attachment_risk in {"High", "Critical"}:
                result["classification"] = "Malicious Attachment"

            result["findings"].append(
                f"Attachment intelligence flagged {attachment_filename} as {attachment_risk} risk."
            )

    result["recommendations"] = build_recommendations(result)

    # Recalculate risk level after attachment scoring
    score = result["threat_score"]

    if score >= 75:
        result["risk_level"] = "Critical"
    elif score >= 50:
        result["risk_level"] = "High"
    elif score >= 25:
        result["risk_level"] = "Medium"
    else:
        result["risk_level"] = "Low"

    # Persist the final upload result after attachment intelligence is applied.
    if result.get("investigation_id"):
        update_investigation_result(result["investigation_id"], result)

    return _privacy_response(result)
