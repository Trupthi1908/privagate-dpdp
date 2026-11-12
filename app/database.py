"""SQLite Audit Trail Logger, Local Cryptographic Vault, & Section 12 DSR Erasure Engine."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_FILE = Path(__file__).resolve().parent.parent / "audit_logs.db"


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target = db_path or DB_FILE
    conn = sqlite3.connect(str(target), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    conn = get_db_connection(db_path)
    with conn:
        # 1. Audit logs table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                request_type TEXT NOT NULL,
                purpose TEXT NOT NULL,
                sentinel_status TEXT NOT NULL DEFAULT 'SAFE',
                sentinel_risk_score INTEGER NOT NULL DEFAULT 0,
                detected_entity_types TEXT NOT NULL,
                entity_count INTEGER NOT NULL,
                sanitized_payload TEXT NOT NULL,
                external_model_used TEXT NOT NULL,
                leakage_count INTEGER NOT NULL,
                reinsertion_accuracy REAL NOT NULL,
                gateway_latency_ms REAL NOT NULL
            )
            """
        )

        # 2. Local cryptographic mapping vault table (DPDP local storage)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_mappings (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                placeholder TEXT NOT NULL,
                original_value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                sha256_fingerprint TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )

        # 3. Section 12 DSR (Right to be Forgotten) Erasure Log
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dsr_erasure_log (
                erasure_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                target_identifier TEXT NOT NULL,
                records_purged INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )

        # Auto-migrate existing table schema if columns are missing
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(audit_logs)")
        existing_cols = [r[1] for r in cursor.fetchall()]
        if "sentinel_status" not in existing_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN sentinel_status TEXT NOT NULL DEFAULT 'SAFE'")
        if "sentinel_risk_score" not in existing_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN sentinel_risk_score INTEGER NOT NULL DEFAULT 0")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vault_req ON vault_mappings(request_id)")
    conn.close()


def log_request(
    request_type: str,
    purpose: str,
    detected_entity_types: List[str] | Dict[str, int],
    entity_count: int,
    sanitized_payload: str,
    external_model_used: str,
    leakage_count: int,
    reinsertion_accuracy: float,
    gateway_latency_ms: float,
    sentinel_status: str = "SAFE",
    sentinel_risk_score: int = 0,
    record_id: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> str:
    init_db(db_path)
    conn = get_db_connection(db_path)
    rec_id = record_id or str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    json_types = json.dumps(detected_entity_types)

    with conn:
        conn.execute(
            """
            INSERT INTO audit_logs (
                id, timestamp, request_type, purpose, sentinel_status, sentinel_risk_score,
                detected_entity_types, entity_count, sanitized_payload, external_model_used,
                leakage_count, reinsertion_accuracy, gateway_latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rec_id,
                ts,
                request_type,
                purpose,
                sentinel_status,
                sentinel_risk_score,
                json_types,
                entity_count,
                sanitized_payload,
                external_model_used,
                leakage_count,
                float(reinsertion_accuracy),
                float(gateway_latency_ms),
            ),
        )
    conn.close()
    return rec_id


def save_vault_mappings(
    request_id: str,
    placeholder_map: Dict[str, str],
    detected_entities: List[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> int:
    """Stores local cryptographic placeholder mappings in the local vault table."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    ts = datetime.now(timezone.utc).isoformat()
    count = 0

    # Build lookup of entity types by text
    text_to_type = {}
    for ent in detected_entities:
        text_to_type[ent.get("text", "").strip().lower()] = ent.get("entity_type", "PII")

    with conn:
        for ph, orig in placeholder_map.items():
            entry_id = str(uuid.uuid4())
            orig_clean = orig.strip()
            etype = text_to_type.get(orig_clean.lower(), "PII")
            sha_fp = hashlib.sha256(orig_clean.encode("utf-8")).hexdigest()

            conn.execute(
                """
                INSERT INTO vault_mappings (
                    id, request_id, placeholder, original_value, entity_type,
                    sha256_fingerprint, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, request_id, ph, orig_clean, etype, sha_fp, ts),
            )
            count += 1
    conn.close()
    return count


def erase_entity_records(
    identifier: str,
    reason: str = "Section 12 DPDP Right to Erasure Request",
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Section 12 Right to be Forgotten:

    Instantly purges all local cryptographic vault records matching the identifier (Name, ID, or Request ID)
    and logs an immutable erasure certificate into dsr_erasure_log.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    erasure_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    query_term = identifier.strip()

    with conn:
        # 1. Count matching vault records
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(*) FROM vault_mappings
            WHERE original_value LIKE ? OR placeholder = ? OR request_id = ?
            """,
            (f"%{query_term}%", query_term, query_term),
        )
        purged_vault_count = cursor.fetchone()[0]

        # 2. Purge from vault_mappings
        conn.execute(
            """
            DELETE FROM vault_mappings
            WHERE original_value LIKE ? OR placeholder = ? OR request_id = ?
            """,
            (f"%{query_term}%", query_term, query_term),
        )

        # 3. Redact any remaining occurrences in sanitized payload audit logs
        conn.execute(
            """
            UPDATE audit_logs
            SET sanitized_payload = REPLACE(sanitized_payload, ?, '[PURGED_UNDER_SECTION_12_DSR]')
            WHERE sanitized_payload LIKE ?
            """,
            (query_term, f"%{query_term}%"),
        )

        # 4. Insert into immutable DSR erasure ledger
        conn.execute(
            """
            INSERT INTO dsr_erasure_log (
                erasure_id, timestamp, target_identifier, records_purged, status, reason
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (erasure_id, ts, query_term, purged_vault_count, "COMPLETED_PURGED", reason),
        )

    conn.close()
    return {
        "erasure_id": erasure_id,
        "timestamp": ts,
        "target_identifier": query_term,
        "records_purged": purged_vault_count,
        "status": "COMPLETED_PURGED",
        "compliance_section": "DPDP Act, 2023 - Section 12 (Right to Erasure)",
    }


def get_dsr_logs(limit: int = 50, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    init_db(db_path)
    lim = limit if isinstance(limit, int) else 50
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT erasure_id, timestamp, target_identifier, records_purged, status, reason
        FROM dsr_erasure_log
        ORDER BY timestamp DESC
        LIMIT ?
        """,
        (lim,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_audit_logs(
    limit: int = 100, offset: int = 0, db_path: Optional[Path] = None
) -> List[Dict[str, Any]]:
    init_db(db_path)
    lim = limit if isinstance(limit, int) else 100
    off = offset if isinstance(offset, int) else 0
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, timestamp, request_type, purpose, sentinel_status, sentinel_risk_score,
               detected_entity_types, entity_count, sanitized_payload, external_model_used,
               leakage_count, reinsertion_accuracy, gateway_latency_ms
        FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (lim, off),
    )
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        d = dict(r)
        try:
            d["detected_entity_types"] = json.loads(d["detected_entity_types"])
        except Exception:
            pass
        result.append(d)
    return result


def get_audit_stats(db_path: Optional[Path] = None) -> Dict[str, Any]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(leakage_count) FROM audit_logs")
    val = cursor.fetchone()[0]
    total_leakage = val if val is not None else 0

    cursor.execute("SELECT AVG(gateway_latency_ms) FROM audit_logs")
    val_lat = cursor.fetchone()[0]
    avg_latency = round(val_lat, 2) if val_lat is not None else 0.0

    cursor.execute("SELECT AVG(reinsertion_accuracy) FROM audit_logs")
    val_acc = cursor.fetchone()[0]
    avg_reinsertion = round(val_acc, 2) if val_acc is not None else 100.0

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE sentinel_status = 'BLOCKED'")
    val_blocked = cursor.fetchone()[0]
    threats_blocked = val_blocked if val_blocked is not None else 0

    cursor.execute("SELECT COUNT(*) FROM dsr_erasure_log")
    dsr_count = cursor.fetchone()[0]

    conn.close()
    return {
        "total_requests": total_requests,
        "total_leakage": total_leakage,
        "avg_latency_ms": avg_latency,
        "avg_reinsertion_accuracy": avg_reinsertion,
        "threats_blocked": threats_blocked,
        "dsr_erasures_executed": dsr_count,
    }
