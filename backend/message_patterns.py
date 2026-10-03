"""Rule-based URL obfuscation and business email compromise indicators."""

from email.utils import getaddresses
from html import unescape
from html.parser import HTMLParser
import ipaddress
import os
import re
import socket
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit
import requests


SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "lnkd.in", "tiny.cc", "soo.gd", "s.id",
}

CONFUSABLE_TRANSLATION = str.maketrans({
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u0456": "i",
    "\u0458": "j", "\u043a": "k", "\u043c": "m", "\u043d": "h",
    "\u043e": "o", "\u0440": "p", "\u0455": "s", "\u0442": "t",
    "\u0443": "y", "\u0445": "x", "\u0432": "b", "\u0501": "d",
    "\u0581": "g", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v",
    "\u03b9": "i", "\u03ba": "k", "\u03c4": "t", "\u03c7": "x",
})
INVISIBLE_CHARACTERS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}


class _AnchorText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            self._current = {"href": href or "", "text": ""}

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"] += data

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current is not None:
            self.links.append(self._current)
            self._current = None


def _host(value: str) -> str:
    try:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        return (parsed.hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


def _domain_signals(url: str) -> list[dict]:
    signals = []
    visible = unescape(url)
    without_invisibles = "".join(char for char in visible if char not in INVISIBLE_CHARACTERS)
    if without_invisibles != visible:
        signals.append({"type": "invisible_character", "detail": "URL contains zero-width or invisible characters."})

    decoded_once = unquote(without_invisibles)
    decoded_twice = unquote(decoded_once)
    normalized = unicodedata.normalize("NFKC", decoded_twice)
    host = _host(normalized)
    original_host = _host(visible)

    if original_host.startswith("xn--") or any(label.startswith("xn--") for label in original_host.split(".")):
        signals.append({"type": "punycode_domain", "detail": "URL uses an IDN punycode domain label."})
    if host and any(char.isascii() is False and char.isalnum() for char in host):
        ascii_spoof = host.translate(CONFUSABLE_TRANSLATION)
        if ascii_spoof != host:
            signals.append({"type": "unicode_lookalike", "detail": f"Unicode hostname resembles {ascii_spoof}."})
        else:
            signals.append({"type": "unicode_hostname", "detail": "URL hostname contains non-ASCII characters."})

    if decoded_once != without_invisibles or decoded_twice != decoded_once:
        signals.append({"type": "percent_encoded", "detail": "URL contains percent-encoded characters that change when decoded."})
    if normalized != decoded_twice:
        signals.append({"type": "unicode_compatibility_encoding", "detail": "URL contains Unicode compatibility characters that normalize to different text."})
    try:
        parsed = urlsplit(normalized if "://" in normalized else f"//{normalized}")
        if parsed.username or parsed.password:
            signals.append({"type": "userinfo", "detail": "URL contains user information before the hostname."})
        parsed_host = parsed.hostname or ""
    except ValueError:
        parsed_host = ""

    if parsed_host:
        try:
            ipaddress.ip_address(parsed_host)
            signals.append({"type": "ip_host", "detail": "URL uses a literal IP address instead of a domain name."})
        except ValueError:
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", parsed_host, re.I):
                signals.append({"type": "numeric_host", "detail": "URL uses an unusual numeric hostname representation."})
        if any(parsed_host == domain or parsed_host.endswith(f".{domain}") for domain in SHORTENER_DOMAINS):
            signals.append({"type": "shortener", "detail": "URL uses a known link-shortening domain; its final destination is not shown here."})

    if re.search(r"https?://[^\s/@]+@", visible, re.I):
        signals.append({"type": "at_sign_host_confusion", "detail": "An @ character can make the displayed URL identity differ from its actual hostname."})

    return signals


def _visible_link_mismatches(email_text: str) -> list[dict]:
    parser = _AnchorText()
    try:
        parser.feed(email_text or "")
    except Exception:
        return []
    mismatches = []
    for link in parser.links:
        destination = _host(unescape(link["href"]))
        visible_text = re.sub(r"\s+", "", unescape(link["text"]))
        visible_host = _host(visible_text)
        if destination and visible_host and destination != visible_host:
            mismatches.append({
                "type": "visible_destination_mismatch",
                "detail": f"Link text shows {visible_host} while its destination is {destination}.",
            })
    return mismatches


def _resolve_shortener(url: str, enabled: bool | None = None) -> dict:
    """Optionally inspect a bounded redirect chain from known shortener hosts only."""
    if enabled is None:
        enabled = os.getenv("ENABLE_SAFE_SHORTENER_RESOLUTION", "false").strip().lower() in {"1", "true", "yes"}
    if not enabled:
        return {"status": "disabled", "chain": [url]}

    current = url
    chain = [url]
    session = requests.Session()
    session.trust_env = False
    try:
        for _ in range(4):
            try:
                parsed = urlsplit(current)
                port = parsed.port
            except ValueError:
                return {"status": "blocked", "chain": chain, "detail": "Malformed redirect URL."}
            host = (parsed.hostname or "").lower().rstrip(".")
            if parsed.scheme.lower() not in {"http", "https"}:
                return {"status": "blocked", "chain": chain, "detail": "Unsupported URL form."}
            if not any(host == domain or host.endswith(f".{domain}") for domain in SHORTENER_DOMAINS):
                return {"status": "resolved", "chain": chain, "destination": current}
            if parsed.scheme.lower() != "https" or parsed.username or parsed.password or port not in {None, 443}:
                return {"status": "blocked", "chain": chain, "detail": "Shortener requests require HTTPS on the default port."}

            try:
                records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                addresses = {record[4][0] for record in records}
                if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
                    return {"status": "blocked", "chain": chain, "detail": "Shortener host did not resolve exclusively to public addresses."}
            except (OSError, ValueError):
                return {"status": "unavailable", "chain": chain, "detail": "Shortener hostname could not be safely resolved."}

            try:
                response = session.get(
                    current,
                    allow_redirects=False,
                    stream=True,
                    timeout=(2, 3),
                    headers={"User-Agent": "Threatloom-Link-Inspector/1.0"},
                )
            except requests.RequestException:
                return {"status": "unavailable", "chain": chain, "detail": "Shortener request failed or timed out."}
            try:
                location = response.headers.get("Location")
                status_code = response.status_code
            finally:
                response.close()

            if status_code < 300 or status_code >= 400 or not location:
                return {"status": "no_redirect", "chain": chain}
            destination = urljoin(current, location)
            if destination in chain:
                return {"status": "loop_detected", "chain": chain + [destination]}
            chain.append(destination)
            current = destination

        return {"status": "hop_limit", "chain": chain}
    finally:
        session.close()


def analyze_obfuscated_urls(
    urls: list[str] | None,
    email_text: str = "",
    resolve_shorteners: bool | None = None,
) -> dict:
    """Describe URL camouflage; optionally inspect only known shortener redirects."""
    if resolve_shorteners is None:
        resolve_shorteners = os.getenv("ENABLE_SAFE_SHORTENER_RESOLUTION", "false").strip().lower() in {"1", "true", "yes"}
    url_results = []
    shortener_results = []
    for raw_url in urls or []:
        signals = _domain_signals(str(raw_url))
        if signals:
            url_results.append({"url": str(raw_url), "signals": signals})
        if any(signal["type"] == "shortener" for signal in signals):
            if len(shortener_results) < 5:
                shortener_results.append({"url": str(raw_url), **_resolve_shortener(str(raw_url), resolve_shorteners)})
            else:
                shortener_results.append({"url": str(raw_url), "status": "limit_reached", "chain": [str(raw_url)]})
    link_mismatches = _visible_link_mismatches(email_text)
    return {
        "status": "signals_found" if url_results or link_mismatches else "no_signals",
        "urls": url_results,
        "url_count": len(urls or []),
        "link_text_signals": link_mismatches,
        "shortener_resolution": {
            "status": "enabled" if resolve_shorteners else "disabled",
            "results": shortener_results,
            "note": "When enabled, requests are limited to known shortener hosts, with public DNS checks, timeouts, and a four-hop cap.",
        },
        "note": "URL patterns are investigation leads; encoded or internationalized URLs can be legitimate.",
    }


def analyze_bec_patterns(email_text: str, headers: dict, url_analysis: dict | None = None, urls: list[str] | None = None) -> dict:
    """Return explainable BEC patterns based on message text and routing headers."""
    text = (email_text or "").lower()
    signals = []

    sender_addresses = getaddresses([str(headers.get("from") or "")])
    reply_addresses = getaddresses([str(headers.get("reply-to") or "")])
    sender_domains = {address.rsplit("@", 1)[-1].lower().strip(" .>") for _, address in sender_addresses if "@" in address}
    reply_domains = {address.rsplit("@", 1)[-1].lower().strip(" .>") for _, address in reply_addresses if "@" in address}
    if sender_domains and reply_domains and sender_domains.isdisjoint(reply_domains):
        signals.append({
            "type": "reply_to_mismatch",
            "severity": "high",
            "detail": f"Reply-To domain(s) {', '.join(sorted(reply_domains))} differ from From domain(s) {', '.join(sorted(sender_domains))}.",
        })

    payment_terms = re.findall(
        r"\b(?:wire transfer|bank account|bank details|routing number|beneficiary|remittance|change(?:d)? (?:the )?(?:bank|payment) details|new account details|payment diversion|transfer funds)\b",
        text,
    )
    if payment_terms:
        signals.append({
            "type": "payment_diversion_language",
            "severity": "high",
            "detail": "Message contains payment-routing or bank-detail change language: " + ", ".join(dict.fromkeys(payment_terms[:5])) + ".",
        })

    invoice_terms = re.findall(r"\b(?:invoice|purchase order|po number|overdue payment|payment due|remit payment)\b", text)
    urgency_terms = re.findall(r"\b(?:immediately|urgent|today|asap|before (?:close of )?business|confidential|keep this private)\b", text)
    if invoice_terms and (payment_terms or urgency_terms):
        signals.append({
            "type": "invoice_payment_pressure",
            "severity": "medium",
            "detail": "Invoice or purchase-order language is combined with payment instructions or urgency.",
        })

    executive_terms = re.findall(r"\b(?:ceo|cfo|chief executive|chief financial officer|managing director|president|founder|executive director)\b", text)
    secrecy_terms = re.findall(r"\b(?:do not call|don't call|keep this confidential|keep this between us|do not discuss|don't discuss)\b", text)
    if executive_terms and (payment_terms or urgency_terms) and secrecy_terms:
        signals.append({
            "type": "executive_impersonation_pattern",
            "severity": "high",
            "detail": "Executive-role language, urgent financial instructions, and secrecy language occur together; verify through a known second channel.",
        })

    credential_terms = re.findall(r"\b(?:password|login credentials|sign in to verify|verify your account|reset your password|one[- ]time code|security code)\b", text)
    has_shortener = any(
        signal.get("type") == "shortener"
        for item in (url_analysis or {}).get("urls", [])
        for signal in item.get("signals", [])
    )
    has_url_signal = bool(urls or (url_analysis or {}).get("urls") or (url_analysis or {}).get("link_text_signals"))
    if credential_terms and has_url_signal:
        signals.append({
            "type": "credential_harvesting_pattern",
            "severity": "high",
            "detail": "Credential or verification language appears with a URL camouflage signal" + (" and a link shortener" if has_shortener else "") + ".",
        })

    strength = "high" if len(signals) >= 3 else "medium" if len(signals) == 2 else "low" if signals else "none"
    return {
        "status": "signals_found" if signals else "no_signals",
        "signals": signals,
        "signal_strength": strength,
        "signal_count": len(signals),
        "note": "Rule-based triage indicators, not a probability or proof of fraud. Confirm payment changes through a known trusted channel.",
    }
