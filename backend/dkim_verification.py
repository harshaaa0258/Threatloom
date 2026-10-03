"""Cryptographic verification for DKIM signatures on raw RFC 5322 messages."""

from email import policy
from email.parser import BytesParser
from collections.abc import Callable
import re

import dkim


_DOMAIN_PATTERN = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)
_SELECTOR_PATTERN = re.compile(r"(?:^|;)\s*s\s*=\s*([^;\s]+)", re.IGNORECASE)
_MAX_SIGNATURES_TO_VERIFY = 5


def verify_dkim_signatures(
    message: bytes,
    dnsfunc: Callable[..., bytes | None] | None = None,
) -> dict:
    """Verify DKIM signatures and report per-signature results."""
    parsed_message = BytesParser(policy=policy.default).parsebytes(message)
    headers = parsed_message.get_all("DKIM-Signature", [])
    if not headers:
        return {
            "status": "not_present",
            "signatures": [],
            "message": "No DKIM-Signature header was found.",
        }

    verification_limited = len(headers) > _MAX_SIGNATURES_TO_VERIFY
    headers_to_verify = headers[:_MAX_SIGNATURES_TO_VERIFY]
    signatures = []
    for index, header in enumerate(headers_to_verify):
        header_value = str(header)
        domain_match = _DOMAIN_PATTERN.search(header_value)
        selector_match = _SELECTOR_PATTERN.search(header_value)
        signature = {
            "domain": domain_match.group(1).strip() if domain_match else None,
            "selector": selector_match.group(1).strip() if selector_match else None,
        }

        if not domain_match or not selector_match:
            signature.update({
                "status": "invalid_header",
                "message": "The DKIM header is missing a signing domain or selector.",
            })
        else:
            try:
                verifier = dkim.DKIM(message)
                if dnsfunc is None:
                    verified = verifier.verify(idx=index)
                else:
                    verified = verifier.verify(idx=index, dnsfunc=dnsfunc)
            except dkim.ValidationError as error:
                signature.update({
                    "status": "fail",
                    "message": "DKIM signature failed cryptographic verification.",
                    "error": str(error),
                })
            except Exception as error:
                signature.update({
                    "status": "error",
                    "message": "DKIM verification could not be completed.",
                    "error": str(error),
                })
            else:
                signature.update({
                    "status": "pass" if verified else "fail",
                    "message": (
                        "DKIM signature cryptographically verified."
                        if verified
                        else "DKIM signature failed cryptographic verification."
                    ),
                })
        signatures.append(signature)

    successful = next(
        (item for item in signatures if item["status"] == "pass"),
        None,
    )
    representative = successful or signatures[0]
    statuses = {item["status"] for item in signatures}
    if successful:
        status = "pass"
        message = "At least one DKIM signature cryptographically verified."
    elif verification_limited:
        status = "partial"
        message = "No checked DKIM signature passed; additional signatures were not checked."
    elif "error" in statuses:
        status = "error"
        message = "DKIM signature verification could not be completed."
    elif "fail" in statuses:
        status = "fail"
        message = "No DKIM signature passed cryptographic verification."
    else:
        status = "invalid_header"
        message = "DKIM-Signature headers could not be parsed for verification."

    return {
        "status": status,
        "domain": representative["domain"],
        "selector": representative["selector"],
        "signatures": signatures,
        "verification_limited": verification_limited,
        "message": message if not verification_limited else (
            f"{message} Only the first {_MAX_SIGNATURES_TO_VERIFY} signatures were checked."
        ),
    }
