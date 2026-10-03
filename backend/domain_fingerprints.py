"""Supplemental WHOIS and passive DNS hosting fingerprints."""

import ipaddress
import os
import re
import socket
import time


WHOIS_CACHE = {}
WHOIS_CACHE_SECONDS = 24 * 60 * 60
WHOIS_ERROR_CACHE_SECONDS = 10 * 60
WHOIS_TIMEOUT_SECONDS = 3
MAX_WHOIS_RESPONSE_BYTES = 64 * 1024

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.publicinterestregistry.org",
    "info": "whois.afilias.net",
    "biz": "whois.nic.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "uk": "whois.nic.uk",
    "me": "whois.nic.me",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "tech": "whois.nic.tech",
    "in": "whois.registry.in",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
}

FIELD_PATTERNS = {
    "registrar": re.compile(r"^(?:Registrar|Sponsoring Registrar)\s*:\s*(.+)$", re.I | re.M),
    "created": re.compile(r"^(?:Creation Date|Created On|Created|Registered On|Registration Date|Domain Registration Date)\s*:\s*(.+)$", re.I | re.M),
    "updated": re.compile(r"^(?:Updated Date|Last Updated On|Last Modified|Changed)\s*:\s*(.+)$", re.I | re.M),
    "expires": re.compile(r"^(?:Registry Expiry Date|Expiration Date|Expiry Date|Expires On|Renewal Date)\s*:\s*(.+)$", re.I | re.M),
}

NS_FINGERPRINTS = [
    (("cloudflare.com",), "Cloudflare DNS"),
    (("awsdns-", "awsdns.com"), "Amazon Route 53"),
    (("azure-dns.",), "Microsoft Azure DNS"),
    (("googledomains.com", "google.com"), "Google managed DNS"),
    (("domaincontrol.com",), "GoDaddy DNS"),
    (("digitalocean.com",), "DigitalOcean DNS"),
    (("linode.com",), "Akamai/Linode DNS"),
    (("nsone.net",), "NS1 DNS"),
    (("dnsmadeeasy.com",), "DNS Made Easy"),
    (("registrar-servers.com",), "Namecheap DNS"),
]

MX_FINGERPRINTS = [
    (("google.com", "googlemail.com"), "Google Workspace mail"),
    (("mail.protection.outlook.com", "outlook.com"), "Microsoft 365 mail"),
    (("zoho.com", "zoho.eu", "zohomail.com"), "Zoho Mail"),
    (("mimecast.com",), "Mimecast mail security"),
    (("pphosted.com", "proofpoint.com"), "Proofpoint mail security"),
    (("barracuda.com",), "Barracuda mail security"),
    (("messagelabs.com",), "Broadcom/Symantec mail security"),
    (("secureserver.net",), "GoDaddy mail service"),
]

CNAME_FINGERPRINTS = [
    (("cloudfront.net",), "Amazon CloudFront"),
    (("azureedge.net", "trafficmanager.net"), "Microsoft Azure edge hosting"),
    (("fastly.net",), "Fastly CDN"),
    (("netlify.app", "netlify.com"), "Netlify hosting"),
    (("vercel-dns.com", "vercel.app"), "Vercel hosting"),
    (("github.io",), "GitHub Pages"),
    (("cdn.cloudflare.net",), "Cloudflare CDN"),
]


def _query_whois_server(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=WHOIS_TIMEOUT_SECONDS) as connection:
        connection.settimeout(WHOIS_TIMEOUT_SECONDS)
        connection.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks = bytearray()
        while len(chunks) < MAX_WHOIS_RESPONSE_BYTES:
            try:
                data = connection.recv(min(4096, MAX_WHOIS_RESPONSE_BYTES - len(chunks)))
            except socket.timeout:
                break
            if not data:
                break
            chunks.extend(data)
    return chunks.decode("utf-8", errors="replace")


def _whois_server_for(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1]
    if tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]
    try:
        response = _query_whois_server("whois.iana.org", tld)
    except OSError:
        return None
    match = re.search(r"^(?:refer|whois)\s*:\s*(\S+)\s*$", response, re.I | re.M)
    if not match:
        return None
    server = match.group(1).strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", server) or ".." in server:
        return None
    try:
        ipaddress.ip_address(server)
        return None
    except ValueError:
        return server


def lookup_traditional_whois(domain: str) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if os.getenv("WHOIS_LOOKUP_ENABLED", "true").strip().lower() not in {"1", "true", "yes"}:
        return {"status": "disabled", "message": "Traditional WHOIS lookup is disabled by configuration."}
    try:
        domain = domain.encode("idna").decode("ascii")
        ipaddress.ip_address(domain)
        return {"status": "not_applicable", "message": "WHOIS domain registration lookup does not apply to IP literals."}
    except ValueError:
        pass
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        return {"status": "invalid", "message": "A valid fully qualified domain name is required."}

    cached = WHOIS_CACHE.get(domain)
    if cached and cached[0] > time.time():
        return dict(cached[1])

    try:
        server = _whois_server_for(domain)
        if not server:
            result = {"status": "unavailable", "message": "No WHOIS referral server was available for this top-level domain."}
            WHOIS_CACHE[domain] = (time.time() + WHOIS_ERROR_CACHE_SECONDS, result)
            return result
        response = _query_whois_server(server, domain)
        if not response.strip() or "no match" in response.lower() or "not found" in response.lower():
            result = {"status": "not_found", "server": server, "message": "WHOIS returned no registration record."}
            WHOIS_CACHE[domain] = (time.time() + WHOIS_ERROR_CACHE_SECONDS, result)
            return result

        parsed = {field: None for field in FIELD_PATTERNS}
        for field, pattern in FIELD_PATTERNS.items():
            match = pattern.search(response)
            if match:
                parsed[field] = match.group(1).strip()
        nameservers = sorted({
            match.group(1).rstrip(".").lower()
            for match in re.finditer(r"^(?:Name Server|Nameserver|nserver)\s*:\s*(\S+)", response, re.I | re.M)
        })
        status_codes = sorted({
            match.group(1).strip()
            for match in re.finditer(r"^(?:Domain Status|Status)\s*:\s*([^\s]+)", response, re.I | re.M)
        })
        result = {
            "status": "found",
            "server": server,
            **parsed,
            "nameservers": nameservers,
            "status_codes": status_codes,
        }
        WHOIS_CACHE[domain] = (time.time() + WHOIS_CACHE_SECONDS, result)
        return result
    except (OSError, socket.gaierror, TimeoutError) as error:
        result = {"status": "unavailable", "message": f"Traditional WHOIS lookup failed: {type(error).__name__}."}
        WHOIS_CACHE[domain] = (time.time() + WHOIS_ERROR_CACHE_SECONDS, result)
        return result


def _matches(hostname: str, patterns: tuple[str, ...]) -> bool:
    hostname = hostname.lower().rstrip(".")
    return any(hostname == pattern or hostname.endswith("." + pattern) or pattern in hostname for pattern in patterns)


def fingerprint_hosting(dns_records: dict | None) -> dict:
    dns_records = dns_records or {}
    observations = []

    for name in dns_records.get("NS", []) or []:
        for patterns, provider in NS_FINGERPRINTS:
            if _matches(str(name), patterns):
                observations.append({"category": "dns_hosting", "provider": provider, "indicator": str(name)})
                break
    for record in dns_records.get("MX", []) or []:
        hostname = str(record).split()[-1].rstrip(".") if record else ""
        for patterns, provider in MX_FINGERPRINTS:
            if hostname and _matches(hostname, patterns):
                observations.append({"category": "mail_hosting", "provider": provider, "indicator": hostname})
                break
    for record in dns_records.get("CNAME", []) or []:
        hostname = str(record).rstrip(".")
        for patterns, provider in CNAME_FINGERPRINTS:
            if hostname and _matches(hostname, patterns):
                observations.append({"category": "web_hosting", "provider": provider, "indicator": hostname})
                break

    provider_names = sorted({item["provider"] for item in observations})
    return {
        "status": "fingerprints_found" if observations else "no_fingerprint_found",
        "providers": provider_names,
        "observations": observations,
        "note": "Provider matches are based on DNS naming patterns and identify likely DNS or mail services, not confirmed web-hosting ownership.",
    }
