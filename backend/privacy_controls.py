"""Persisted retention settings and output-only PII masking helpers."""

import ipaddress
import os
import re
import sqlite3


EMAIL_PATTERN = re.compile(r"\b([A-Z0-9._%+-]{1,64})@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_PATTERN = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{0,39}(?![0-9A-Fa-f:])")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes"}


def _initial_retention_days() -> int:
    try:
        value = int(os.getenv("INVESTIGATION_RETENTION_DAYS", "0"))
    except ValueError:
        value = 0
    return max(0, min(value, 3650))


def initialize_privacy_settings(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS privacy_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            retention_days INTEGER NOT NULL DEFAULT 0,
            mask_email_addresses INTEGER NOT NULL DEFAULT 0,
            mask_ip_addresses INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
    """)
    connection.execute(
        "INSERT OR IGNORE INTO privacy_settings (id, retention_days, mask_email_addresses, mask_ip_addresses, updated_at) VALUES (1, ?, ?, ?, datetime('now'))",
        (
            _initial_retention_days(),
            int(_env_bool("MASK_EMAIL_ADDRESSES")),
            int(_env_bool("MASK_IP_ADDRESSES")),
        ),
    )


def get_privacy_settings(db_path: str) -> dict:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT retention_days, mask_email_addresses, mask_ip_addresses, updated_at FROM privacy_settings WHERE id = 1"
        ).fetchone()
        if row is None:
            return {"retention_days": 0, "mask_email_addresses": False, "mask_ip_addresses": False, "updated_at": None}
        return {
            "retention_days": row["retention_days"],
            "mask_email_addresses": bool(row["mask_email_addresses"]),
            "mask_ip_addresses": bool(row["mask_ip_addresses"]),
            "updated_at": row["updated_at"],
        }
    finally:
        connection.close()


def update_privacy_settings(db_path: str, values: dict) -> dict:
    allowed = {"retention_days", "mask_email_addresses", "mask_ip_addresses"}
    changes = {key: value for key, value in values.items() if key in allowed and value is not None}
    if not changes:
        return get_privacy_settings(db_path)
    assignments = [f"{field} = ?" for field in changes]
    parameters = [int(value) if field.startswith("mask_") else value for field, value in changes.items()]
    assignments.append("updated_at = datetime('now')")
    connection = sqlite3.connect(db_path)
    try:
        connection.execute(
            f"UPDATE privacy_settings SET {', '.join(assignments)} WHERE id = 1",
            parameters,
        )
        connection.commit()
    finally:
        connection.close()
    return get_privacy_settings(db_path)


def _mask_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if address.version == 4:
        first_two = str(address).split(".")[:2]
        return ".".join(first_two + ["xxx", "xxx"])
    hextets = address.exploded.split(":")
    return ":".join(hextets[:3] + ["xxxx"] * 5)


def _mask_string(value: str, mask_emails: bool, mask_ips: bool) -> str:
    if mask_emails:
        value = EMAIL_PATTERN.sub(lambda match: f"{match.group(1)[:1]}***@{match.group(2)}", value)
    if mask_ips:
        def replace_ip(match):
            return _mask_ip(match.group(0))

        value = IPV4_PATTERN.sub(replace_ip, value)
        value = IPV6_PATTERN.sub(replace_ip, value)
    return value


def mask_sensitive_data(value, settings: dict):
    mask_emails = bool(settings.get("mask_email_addresses"))
    mask_ips = bool(settings.get("mask_ip_addresses"))
    if not mask_emails and not mask_ips:
        return value
    if isinstance(value, str):
        return _mask_string(value, mask_emails, mask_ips)
    if isinstance(value, list):
        return [mask_sensitive_data(item, settings) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_sensitive_data(item, settings) for item in value)
    if isinstance(value, dict):
        return {
            _mask_string(key, mask_emails, mask_ips) if isinstance(key, str) else key:
            mask_sensitive_data(item, settings)
            for key, item in value.items()
        }
    return value
