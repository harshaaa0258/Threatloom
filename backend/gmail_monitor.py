"""Read-only, near-real-time Gmail inbox monitor using Gmail history cursors."""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import logging
import os
import sqlite3
import threading
import time

import requests


GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URL = "https://oauth2.googleapis.com/token"
MAX_MESSAGE_BYTES = 10 * 1024 * 1024
MAX_ANALYSIS_CHARS = 250_000


class GmailApiError(Exception):
    def __init__(self, status_code: int, error_code: str = "gmail_api_error"):
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(error_code)


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _message_analysis_text(raw_message: bytes) -> str:
    """Extract headers, text bodies, and attachment names without retaining MIME bytes."""
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    lines = [f"{name}: {value}" for name, value in message.items()]
    body_parts: list[str] = []
    attachment_names: list[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            safe_name = " ".join(str(filename or "unnamed attachment").split())[:255]
            attachment_names.append(f"{safe_name} ({part.get_content_type()})")
            continue

        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue

        try:
            content = part.get_content()
        except (LookupError, UnicodeError, AttributeError, TypeError, KeyError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        if content:
            body_parts.append(str(content))

    if attachment_names:
        lines.extend(f"X-Threatloom-Attachment: {name}" for name in attachment_names)

    body = "\n\n".join(body_parts)
    if len(body) > MAX_ANALYSIS_CHARS:
        body = body[:MAX_ANALYSIS_CHARS]
    return "\n".join(lines) + "\n\n" + body


class GmailInboxMonitor:
    """Poll Gmail history for newly added Inbox messages and analyze them once."""

    def __init__(self, db_path: str, analyze_message):
        self.db_path = db_path
        self.analyze_message = analyze_message
        self.client_id = os.getenv("GMAIL_CLIENT_ID", "").strip()
        self.client_secret = os.getenv("GMAIL_CLIENT_SECRET", "").strip()
        self.refresh_token = os.getenv("GMAIL_REFRESH_TOKEN", "").strip()
        self.enabled = _enabled(os.getenv("GMAIL_MONITOR_ENABLED")) and all(
            (self.client_id, self.client_secret, self.refresh_token)
        )
        self.external_intel_enabled = _enabled(os.getenv("GMAIL_ENABLE_EXTERNAL_INTEL"))
        try:
            configured_interval = int(os.getenv("GMAIL_POLL_INTERVAL_SECONDS", "30"))
        except ValueError:
            configured_interval = 30
        self.poll_interval = max(15, min(configured_interval, 300))
        self._status_lock = threading.Lock()
        self._token_lock = threading.Lock()
        self._access_token = None
        self._access_token_expires_at = 0.0
        self._status = {
            "state": "starting" if self.enabled else "not_configured",
            "last_sync_at": None,
            "last_error": None,
        }

    def initialize(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        connection = sqlite3.connect(self.db_path, timeout=15)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS gmail_monitor_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS gmail_processed_messages (
                    message_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            connection.commit()
        finally:
            connection.close()

    def public_status(self) -> dict:
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            processed = connection.execute(
                "SELECT COUNT(*) FROM gmail_processed_messages WHERE status = 'processed'"
            ).fetchone()[0]
            skipped = connection.execute(
                "SELECT COUNT(*) FROM gmail_processed_messages WHERE status LIKE 'skipped_%'"
            ).fetchone()[0]
        finally:
            connection.close()

        with self._status_lock:
            current = dict(self._status)
        return {
            "enabled": self.enabled,
            "state": current["state"],
            "poll_interval_seconds": self.poll_interval,
            "last_sync_at": current["last_sync_at"],
            "last_error": current["last_error"],
            "processed_messages": processed,
            "skipped_messages": skipped,
            "external_intel_enabled": self.external_intel_enabled,
            "new_mail_only": True,
            "message_bodies_retained": False,
        }

    def _set_status(self, *, state: str | None = None, last_error: str | None = None, synced: bool = False):
        with self._status_lock:
            if state is not None:
                self._status["state"] = state
            self._status["last_error"] = last_error
            if synced:
                self._status["last_sync_at"] = _now()

    def _get_state(self, key: str) -> str | None:
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            row = connection.execute(
                "SELECT value FROM gmail_monitor_state WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else None
        finally:
            connection.close()

    def _set_state(self, key: str, value: str) -> None:
        connection = sqlite3.connect(self.db_path, timeout=10)
        try:
            connection.execute(
                "INSERT INTO gmail_monitor_state(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            connection.commit()
        finally:
            connection.close()

    def _refresh_access_token(self) -> str:
        with self._token_lock:
            now = time.monotonic()
            if self._access_token and self._access_token_expires_at > now + 60:
                return self._access_token

            response = requests.post(
                TOKEN_URL,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": self.refresh_token,
                    "grant_type": "refresh_token",
                },
                timeout=(5, 15),
            )
            if response.status_code >= 400:
                self._access_token = None
                self._access_token_expires_at = 0.0
                raise GmailApiError(response.status_code, "authorization_required")
            token_data = response.json()
            token = token_data.get("access_token")
            if not token:
                raise GmailApiError(502, "token_response_invalid")
            self._access_token = token
            self._access_token_expires_at = now + int(token_data.get("expires_in", 3600) or 3600)
            return token

    @staticmethod
    def _api_get(access_token: str, path: str, params: dict | None = None) -> dict:
        response = requests.get(
            f"{GMAIL_API}/{path.lstrip('/')}",
            params=params or {},
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=(5, 20),
        )
        if response.status_code >= 400:
            error_code = "gmail_api_error"
            try:
                error = response.json().get("error", {})
                error_code = str(error.get("status") or error.get("errors", [{}])[0].get("reason") or error_code)
            except (ValueError, AttributeError, IndexError):
                pass
            raise GmailApiError(response.status_code, error_code[:80])
        return response.json()

    def _claim_message(self, message_id: str) -> bool:
        now = _now()
        connection = sqlite3.connect(self.db_path, timeout=15)
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT OR IGNORE INTO gmail_processed_messages(message_id, status, updated_at) VALUES (?, 'processing', ?)",
                (message_id, now),
            )
            if cursor.rowcount == 1:
                connection.commit()
                return True
            row = connection.execute(
                "SELECT status, updated_at FROM gmail_processed_messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            if row and row[0] == "processing":
                try:
                    stale = (datetime.now(timezone.utc) - datetime.fromisoformat(row[1])).total_seconds() > 600
                except ValueError:
                    stale = True
                if stale:
                    connection.execute(
                        "UPDATE gmail_processed_messages SET updated_at = ? WHERE message_id = ? AND status = 'processing'",
                        (now, message_id),
                    )
                    connection.commit()
                    return True
            connection.commit()
            return False
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _finish_message(self, message_id: str, status: str) -> None:
        connection = sqlite3.connect(self.db_path, timeout=15)
        try:
            connection.execute(
                "UPDATE gmail_processed_messages SET status = ?, updated_at = ? WHERE message_id = ?",
                (status, _now(), message_id),
            )
            connection.commit()
        finally:
            connection.close()

    def _release_message(self, message_id: str) -> None:
        connection = sqlite3.connect(self.db_path, timeout=15)
        try:
            connection.execute(
                "DELETE FROM gmail_processed_messages WHERE message_id = ? AND status = 'processing'",
                (message_id,),
            )
            connection.commit()
        finally:
            connection.close()

    def _process_message(self, access_token: str, message_id: str) -> None:
        if not self._claim_message(message_id):
            return
        try:
            metadata = self._api_get(
                access_token,
                f"messages/{message_id}",
                {"format": "metadata", "fields": "id,labelIds,sizeEstimate"},
            )
            if "INBOX" not in metadata.get("labelIds", []):
                self._finish_message(message_id, "skipped_not_in_inbox")
                return
            if int(metadata.get("sizeEstimate", 0) or 0) > MAX_MESSAGE_BYTES:
                self._finish_message(message_id, "skipped_too_large")
                return

            raw = self._api_get(
                access_token,
                f"messages/{message_id}",
                {"format": "raw", "fields": "id,raw,sizeEstimate"},
            ).get("raw")
            if not raw:
                self._finish_message(message_id, "skipped_no_content")
                return
            raw_bytes = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            if len(raw_bytes) > MAX_MESSAGE_BYTES:
                self._finish_message(message_id, "skipped_too_large")
                return

            analysis_text = _message_analysis_text(raw_bytes)
            self.analyze_message(analysis_text, self.external_intel_enabled)
            self._finish_message(message_id, "processed")
        except GmailApiError as error:
            if error.status_code == 404:
                self._finish_message(message_id, "skipped_unavailable")
                return
            self._release_message(message_id)
            raise
        except Exception:
            self._release_message(message_id)
            raise

    def sync_once(self) -> None:
        if not self.enabled:
            self._set_status(state="not_configured", last_error=None)
            return

        try:
            access_token = self._refresh_access_token()
            profile = self._api_get(access_token, "profile")
            history_id = str(profile.get("historyId") or "")
            account_hash = hashlib.sha256(
                str(profile.get("emailAddress") or "").strip().lower().encode("utf-8")
            ).hexdigest()
            if not history_id or not profile.get("emailAddress"):
                raise GmailApiError(502, "profile_response_invalid")

            cursor = self._get_state("history_id")
            previous_account_hash = self._get_state("account_hash")
            if not cursor or previous_account_hash != account_hash:
                connection = sqlite3.connect(self.db_path, timeout=15)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("DELETE FROM gmail_processed_messages")
                    connection.execute(
                        "INSERT INTO gmail_monitor_state(key, value) VALUES ('account_hash', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (account_hash,),
                    )
                    connection.execute(
                        "INSERT INTO gmail_monitor_state(key, value) VALUES ('history_id', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (history_id,),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
                self._set_status(state="monitoring_new_mail", last_error=None, synced=True)
                return

            start_cursor = cursor
            page_token = None
            page_count = 0
            while page_count < 20:
                params = {
                    "startHistoryId": start_cursor,
                    "historyTypes": "messageAdded",
                    "maxResults": 100,
                }
                if page_token:
                    params["pageToken"] = page_token
                try:
                    page = self._api_get(access_token, "history", params)
                except GmailApiError as error:
                    if error.status_code == 404:
                        self._set_state("history_id", history_id)
                        self._set_status(state="monitoring_new_mail", last_error="history_cursor_reset", synced=True)
                        return
                    raise

                records = page.get("history", [])
                for record in records:
                    record_id = str(record.get("id") or "")
                    for added in record.get("messagesAdded", []):
                        message = added.get("message", {})
                        message_id = str(message.get("id") or "")
                        if message_id:
                            self._process_message(access_token, message_id)
                    if record_id:
                        self._set_state("history_id", record_id)
                        start_cursor = record_id

                page_token = page.get("nextPageToken")
                page_count += 1
                if not page_token:
                    latest_history_id = str(page.get("historyId") or start_cursor)
                    self._set_state("history_id", latest_history_id)
                    break

            self._set_status(state="monitoring_new_mail", last_error=None, synced=True)
        except GmailApiError as error:
            error_state = "authorization_required" if error.status_code in {400, 401, 403} else "service_unavailable"
            self._set_status(state=error_state, last_error=error.error_code)
            logging.warning("Gmail monitor sync failed (%s).", error.error_code)
        except (requests.RequestException, ValueError, KeyError, TypeError):
            self._set_status(state="service_unavailable", last_error="network_or_response_error")
            logging.warning("Gmail monitor sync failed due to a network or response error.")
        except Exception as error:
            self._set_status(state="analysis_error", last_error="message_analysis_error")
            logging.error("Gmail monitor could not analyze a newly received message (%s).", type(error).__name__)

    async def run(self) -> None:
        while True:
            if self.enabled:
                await asyncio.to_thread(self.sync_once)
                await asyncio.sleep(self.poll_interval)
            else:
                self._set_status(state="not_configured", last_error=None)
                await asyncio.sleep(60)
