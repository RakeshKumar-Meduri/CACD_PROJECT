"""
database.py — SQLite helper for Security Log Analyzer.

Responsibilities:
  - Init the `logs` and `alerts` tables on first run.
  - CRUD helpers used by hash_chain.py, detection_engine.py, and app.py.

No external dependencies — uses only Python built-ins: sqlite3, datetime, pandas.
"""

import sqlite3
import pandas as pd
from datetime import datetime

# Path to the SQLite database file (auto-created on first run).
DB_PATH = "logs.db"


# ---------------------------------------------------------------------------
# Internal helper — get a fresh connection each time (thread-safe for Streamlit)
# ---------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    """Return a new SQLite connection to logs.db with row_factory set."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


# ---------------------------------------------------------------------------
# STEP 1-A: init_db — create tables if they don't already exist
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create `logs` and `alerts` tables in logs.db if they don't exist yet.
    Safe to call multiple times — uses IF NOT EXISTS.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    # --- logs table ---------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            username    TEXT NOT NULL,
            source_ip   TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            raw_entry   TEXT NOT NULL,
            entry_hash  TEXT NOT NULL
        )
    """)

    # --- alerts table -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id      INTEGER NOT NULL,
            reason      TEXT NOT NULL,
            severity    TEXT NOT NULL,
            created_at  TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# STEP 1-B: insert_log
# ---------------------------------------------------------------------------

def insert_log(
    timestamp: str,
    username: str,
    source_ip: str,
    event_type: str,
    raw_entry: str,
    entry_hash: str,
) -> int:
    """
    Insert one log row and return its auto-generated id.

    Parameters
    ----------
    timestamp   : ISO-format string, e.g. "2024-01-15 03:22:11"
    username    : e.g. "alice"
    source_ip   : e.g. "192.168.1.10"
    event_type  : "login_success" or "login_failed"
    raw_entry   : concatenated string "timestamp|username|source_ip|event_type"
    entry_hash  : SHA-256 hex digest (computed by hash_chain.py)

    Returns
    -------
    int  — the new row's id (used by insert_alert and the tampering demo)
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO logs (timestamp, username, source_ip, event_type, raw_entry, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, username, source_ip, event_type, raw_entry, entry_hash),
    )
    conn.commit()
    new_id = cursor.lastrowid  # the AUTOINCREMENT id just assigned
    conn.close()
    return new_id


# ---------------------------------------------------------------------------
# STEP 1-C: get_all_logs
# ---------------------------------------------------------------------------

def get_all_logs() -> pd.DataFrame:
    """
    Return every row from the `logs` table as a pandas DataFrame,
    ordered by id ascending (oldest first).

    Returns an empty DataFrame (with the correct columns) if the table is empty.
    """
    conn = _get_connection()
    df = pd.read_sql_query(
        "SELECT id, timestamp, username, source_ip, event_type, raw_entry, entry_hash "
        "FROM logs ORDER BY id ASC",
        conn,
    )
    conn.close()
    return df


# ---------------------------------------------------------------------------
# STEP 1-D: get_last_hash
# ---------------------------------------------------------------------------

def get_last_hash() -> str:
    """
    Return the entry_hash of the most recently inserted log row.
    Returns an empty string "" if the table has no rows yet.

    This is the 'previous_hash' used to start the SHA-256 chain.
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT entry_hash FROM logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row["entry_hash"] if row else ""


# ---------------------------------------------------------------------------
# STEP 1-E: update_raw_entry  (used ONLY by the tampering demo in app.py)
# ---------------------------------------------------------------------------

def update_raw_entry(log_id: int, new_raw_entry: str) -> None:
    """
    Overwrite the raw_entry field of one log row WITHOUT changing entry_hash.
    This deliberately breaks the hash chain at that row — used to demo tampering.

    Parameters
    ----------
    log_id        : the id of the row to corrupt
    new_raw_entry : the fake / edited content to inject
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE logs SET raw_entry = ? WHERE id = ?",
        (new_raw_entry, log_id),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# STEP 1-F: insert_alert
# ---------------------------------------------------------------------------

def insert_alert(log_id: int, reason: str, severity: str) -> None:
    """
    Record an anomaly alert linked to a specific log row.

    Parameters
    ----------
    log_id   : foreign key — the id of the flagged log row
    reason   : one of "failed_login_burst" | "blacklisted_ip" | "off_hours" |
               "z_score_anomaly" | "tampering"
    severity : "Low" | "Medium" | "High"
    """
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO alerts (log_id, reason, severity, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (log_id, reason, severity, datetime.now().isoformat(sep=" ", timespec="seconds")),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# STEP 1-G: get_all_alerts
# ---------------------------------------------------------------------------

def get_all_alerts() -> pd.DataFrame:
    """
    Return all alert rows as a pandas DataFrame, newest first.
    Returns an empty DataFrame (with correct columns) if no alerts exist yet.
    """
    conn = _get_connection()
    df = pd.read_sql_query(
        "SELECT id, log_id, reason, severity, created_at "
        "FROM alerts ORDER BY id DESC",
        conn,
    )
    conn.close()
    return df


# ---------------------------------------------------------------------------
# STEP 1-H: reset_db — clear all data (useful for clean demo resets)
# ---------------------------------------------------------------------------

def reset_db() -> None:
    """Clear all records from logs and alerts tables and reset auto-increment counters."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM logs")
    try:
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('logs', 'alerts')")
    except Exception:
        pass
    conn.commit()
    conn.close()


def delete_alert_by_id(alert_id: int) -> None:
    """Remove a specific alert row by id (incident resolution)."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Quick self-test (run `python database.py` directly to verify)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[database.py] Running self-test ...")

    init_db()
    print("  init_db()          -> OK")

    row_id = insert_log(
        timestamp="2024-01-15 10:00:00",
        username="test_user",
        source_ip="10.0.0.1",
        event_type="login_success",
        raw_entry="2024-01-15 10:00:00|test_user|10.0.0.1|login_success",
        entry_hash="DUMMY_HASH_FOR_TEST",
    )
    print(f"  insert_log()       -> new id = {row_id}")

    last_hash = get_last_hash()
    print(f"  get_last_hash()    -> '{last_hash}'")

    df_logs = get_all_logs()
    print(f"  get_all_logs()     -> {len(df_logs)} row(s)")

    insert_alert(log_id=row_id, reason="off_hours", severity="Low")
    print("  insert_alert()     -> OK")

    df_alerts = get_all_alerts()
    print(f"  get_all_alerts()  -> {len(df_alerts)} row(s)")

    update_raw_entry(log_id=row_id, new_raw_entry="TAMPERED_DATA")
    df_after = get_all_logs()
    tampered_val = df_after.loc[df_after["id"] == row_id, "raw_entry"].values[0]
    print(f"  update_raw_entry() -> raw_entry now = '{tampered_val}'")

    print("\n[database.py] All checks PASSED")
