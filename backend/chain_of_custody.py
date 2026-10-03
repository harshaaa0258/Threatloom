"""Append-only evidence ledger and optional preserved source-message artifacts."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def initialize_evidence_tables(connection: sqlite3.Connection) -> None:
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_ledger_investigation
        ON evidence_ledger(investigation_id, id)
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_artifacts (
            investigation_id INTEGER PRIMARY KEY,
            source_sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            content BLOB NOT NULL,
            stored_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS evidence_ledger_no_update
        BEFORE UPDATE ON evidence_ledger
        BEGIN
            SELECT RAISE(ABORT, 'evidence ledger entries are append-only');
        END
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS evidence_ledger_no_delete
        BEFORE DELETE ON evidence_ledger
        BEGIN
            SELECT RAISE(ABORT, 'evidence ledger entries are append-only');
        END
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS purge_artifact_after_investigation_delete
        AFTER DELETE ON investigations
        BEGIN
            DELETE FROM evidence_artifacts WHERE investigation_id = OLD.id;
        END
    """)


def _canonical_hash(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_bytes(serialized.encode("utf-8"))


def _source_payload(cursor: sqlite3.Cursor, investigation_id: int) -> dict | None:
    row = cursor.execute(
        "SELECT payload_json FROM evidence_ledger WHERE investigation_id = ? ORDER BY id LIMIT 1",
        (investigation_id,),
    ).fetchone()
    return json.loads(row[0]) if row else None


def append_evidence_event(
    db_path: str,
    investigation_id: int,
    event_type: str,
    actor: str = "system",
    actor_is_authenticated: bool = False,
    notes: str = "",
    source_sha256: str | None = None,
    analysis_text_sha256: str | None = None,
    byte_length: int | None = None,
    details: dict | None = None,
    source_content: bytes | None = None,
    preserve_source: bool = False,
    max_artifact_bytes: int = 10 * 1024 * 1024,
) -> dict:
    connection = sqlite3.connect(db_path, timeout=15)
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.cursor()
        if source_sha256 is None:
            source = _source_payload(cursor, investigation_id)
            if source is None:
                raise ValueError("No intake evidence record exists for this investigation.")
            source_sha256 = source.get("source_sha256")
            analysis_text_sha256 = source.get("analysis_text_sha256")
            byte_length = source.get("byte_length")

        previous = cursor.execute(
            "SELECT record_hash FROM evidence_ledger ORDER BY id DESC LIMIT 1"
        ).fetchone()
        event_details = dict(details or {})
        should_store = bool(
            event_type == "message_received"
            and source_content is not None
            and preserve_source
            and len(source_content) <= max_artifact_bytes
        )
        if event_type == "message_received":
            if not preserve_source or source_content is None:
                event_details["artifact_status"] = "not_stored_by_configuration"
            elif len(source_content) > max_artifact_bytes:
                event_details["artifact_status"] = "not_stored_size_limit"
            else:
                event_details["artifact_status"] = "stored"

        payload = {
            "investigation_id": investigation_id,
            "event_type": event_type,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_is_authenticated": actor_is_authenticated,
            "notes": notes,
            "source_sha256": source_sha256,
            "analysis_text_sha256": analysis_text_sha256,
            "byte_length": byte_length,
            "previous_hash": previous[0] if previous else "",
            "details": event_details,
        }
        record_hash = _canonical_hash(payload)
        cursor.execute(
            "INSERT INTO evidence_ledger (investigation_id, payload_json, record_hash) VALUES (?, ?, ?)",
            (investigation_id, json.dumps(payload, ensure_ascii=False), record_hash),
        )
        record_id = cursor.lastrowid

        if should_store:
            cursor.execute(
                "INSERT INTO evidence_artifacts (investigation_id, source_sha256, byte_length, content, stored_at) VALUES (?, ?, ?, ?, ?)",
                (investigation_id, source_sha256, len(source_content), source_content, payload["recorded_at"]),
            )
        connection.commit()
        return {"id": record_id, **payload, "record_hash": record_hash}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_evidence_bundle(db_path: str, investigation_id: int) -> dict | None:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT id, investigation_id, payload_json, record_hash FROM evidence_ledger ORDER BY id"
        ).fetchall()
        entries = []
        previous_hash = ""
        verified = True
        failed_entry_id = None
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
                expected_hash = _canonical_hash(payload)
                payload_valid = isinstance(payload, dict) and payload.get("previous_hash") == previous_hash and row["record_hash"] == expected_hash
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = None
                payload_valid = False
            if not payload_valid:
                verified = False
                if failed_entry_id is None:
                    failed_entry_id = row["id"]
            previous_hash = row["record_hash"]
            if row["investigation_id"] == investigation_id:
                if isinstance(payload, dict):
                    entries.append({"id": row["id"], **payload, "record_hash": row["record_hash"]})
                else:
                    entries.append({"id": row["id"], "investigation_id": investigation_id, "event_type": "corrupt_payload", "record_hash": row["record_hash"]})

        if not entries:
            return None

        first = entries[0]
        artifact = connection.execute(
            "SELECT source_sha256, byte_length, content, stored_at FROM evidence_artifacts WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        if artifact is None:
            if any(entry.get("details", {}).get("artifact_status") == "stored" for entry in entries):
                artifact_status = "missing"
            elif any(entry.get("event_type") == "artifact_purged" for entry in entries):
                artifact_status = "purged"
            else:
                artifact_status = first.get("details", {}).get("artifact_status", "not_available")
            artifact_verified = None
        else:
            artifact_verified = (
                artifact["source_sha256"] == first.get("source_sha256")
                and artifact["byte_length"] == len(artifact["content"])
                and sha256_bytes(artifact["content"]) == first.get("source_sha256")
            )
            artifact_status = "verified" if artifact_verified else "integrity_mismatch"

        return {
            "source": {
                "sha256": first.get("source_sha256"),
                "analysis_text_sha256": first.get("analysis_text_sha256"),
                "byte_length": first.get("byte_length"),
                "artifact_status": artifact_status,
                "artifact_verified": artifact_verified,
                "stored_at": artifact["stored_at"] if artifact else None,
            },
            "events": entries,
            "ledger_integrity": {
                "verified": verified,
                "entries_verified": len(rows) if verified else None,
                "entry_count": len(entries),
                "global_chain_entry_count": len(rows),
                "first_failed_entry_id": failed_entry_id,
            },
            "note": (
                "Custody events recorded through the authenticated API have token-verified actor labels. "
                "Internal system labels and actor tokens do not establish a person's legal identity."
            ),
        }
    finally:
        connection.close()


def get_verified_source_artifact(db_path: str, investigation_id: int) -> tuple[bytes | None, str]:
    bundle = get_evidence_bundle(db_path, investigation_id)
    if bundle is None:
        return None, "not_available"
    if not bundle["ledger_integrity"]["verified"]:
        return None, "ledger_integrity_mismatch"
    connection = sqlite3.connect(db_path)
    try:
        artifact = connection.execute(
            "SELECT source_sha256, byte_length, content FROM evidence_artifacts WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        source = connection.execute(
            "SELECT payload_json FROM evidence_ledger WHERE investigation_id = ? ORDER BY id LIMIT 1",
            (investigation_id,),
        ).fetchone()
        if artifact is None or source is None:
            return None, "not_available"
        source_payload = json.loads(source[0])
        content = artifact[2]
        if (
            artifact[0] != source_payload.get("source_sha256")
            or artifact[1] != len(content)
            or sha256_bytes(content) != source_payload.get("source_sha256")
        ):
            return None, "integrity_mismatch"
        return content, "verified"
    finally:
        connection.close()


def purge_source_artifact(db_path: str, investigation_id: int, actor: str, reason: str) -> bool:
    connection = sqlite3.connect(db_path)
    try:
        artifact_exists = connection.execute(
            "SELECT 1 FROM evidence_artifacts WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()
    finally:
        connection.close()
    if artifact_exists is None:
        return False

    append_evidence_event(
        db_path,
        investigation_id,
        "artifact_purged",
        actor=actor,
        notes=reason,
        details={"artifact_status": "purged"},
    )
    connection = sqlite3.connect(db_path)
    try:
        connection.execute("DELETE FROM evidence_artifacts WHERE investigation_id = ?", (investigation_id,))
        connection.commit()
    finally:
        connection.close()
    return True
