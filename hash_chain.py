"""
hash_chain.py — SHA-256 hash chaining for Security Log Analyzer.

Every log entry's hash depends on its own content AND the previous entry's hash,
forming a tamper-evident chain: modifying any row breaks that row's hash and all
hashes that follow it (because they were computed from the now-wrong stored value).

Functions
---------
compute_hash(raw_entry, previous_hash) -> str
    Computes SHA-256(raw_entry + previous_hash) — the core chain primitive.

add_log_entry(timestamp, username, source_ip, event_type) -> int
    Builds raw_entry, fetches the previous hash from DB, computes the new hash,
    inserts the row, and returns the new log id.

verify_chain() -> list[dict]
    Re-walks every log row in order, recomputes expected hashes, and reports
    which rows are "OK" or "TAMPERED".
"""

import hashlib
import database  # our own module — no external dependencies


# ---------------------------------------------------------------------------
# compute_hash
# ---------------------------------------------------------------------------

def compute_hash(raw_entry: str, previous_hash: str) -> str:
    """
    Return the SHA-256 hex digest of (raw_entry + previous_hash).

    The concatenation order is intentional: raw_entry first, then the chain
    anchor.  Changing either input changes the output entirely (avalanche effect).

    Parameters
    ----------
    raw_entry     : "timestamp|username|source_ip|event_type"
    previous_hash : hex digest of the previous log entry, or "" for the first row

    Returns
    -------
    str  — 64-character lowercase hex string
    """
    combined = raw_entry + previous_hash
    return hashlib.sha256(combined.encode()).hexdigest()


# ---------------------------------------------------------------------------
# add_log_entry
# ---------------------------------------------------------------------------

def add_log_entry(
    timestamp: str,
    username: str,
    source_ip: str,
    event_type: str,
) -> int:
    """
    Build a new chained log entry and persist it to the database.

    Steps:
      1. Construct raw_entry from the four fields.
      2. Fetch the most recent stored hash (empty string if DB is empty).
      3. Compute SHA-256(raw_entry + previous_hash).
      4. Insert the full row via database.insert_log().
      5. Return the new row's id.

    Parameters
    ----------
    timestamp  : ISO-format datetime string, e.g. "2024-01-15 03:22:11"
    username   : login username, e.g. "alice"
    source_ip  : client IP address string, e.g. "192.168.1.10"
    event_type : "login_success" or "login_failed"

    Returns
    -------
    int  — the auto-generated id of the newly inserted log row
    """
    # Step 1: build the canonical plaintext string for this entry
    raw_entry = f"{timestamp}|{username}|{source_ip}|{event_type}"

    # Step 2: get the hash of the last row (or "" if this is the very first row)
    previous_hash = database.get_last_hash()

    # Step 3: compute this entry's hash, chaining it to the previous one
    new_hash = compute_hash(raw_entry, previous_hash)

    # Step 4: persist to SQLite
    log_id = database.insert_log(
        timestamp=timestamp,
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        raw_entry=raw_entry,
        entry_hash=new_hash,
    )

    return log_id


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------

def verify_chain() -> list:
    """
    Walk every log row in insertion order, recompute each expected hash, and
    compare it to the stored hash.

    Chain-walk rule
    ---------------
    After checking each row, set previous_hash = row.entry_hash  (the STORED
    hash, not the recomputed one).  This means:

    - If only raw_entry was silently edited (entry_hash left alone), exactly
      that one row shows "TAMPERED".  Subsequent rows still chain correctly
      from the unchanged stored hash, so they pass — but the tampered row
      itself is clearly exposed.

    - If an attacker also regenerated subsequent hashes, those rows would pass
      here but the original chain snapshot (e.g. a trusted backup) would not
      match.  For this demo, a single-row silent edit is the relevant attack.

    Returns
    -------
    list[dict]  — one dict per row with keys:
        log_id         : int
        stored_hash    : str  (what the DB contains)
        recomputed_hash: str  (what we'd expect if the entry were untouched)
        status         : "OK" or "TAMPERED"
    """
    df = database.get_all_logs()

    previous_hash = ""   # chain starts with an empty anchor (no row 0)
    results = []

    for _, row in df.iterrows():
        # Recompute hash from the raw_entry as it exists NOW in the DB
        recomputed = compute_hash(row["raw_entry"], previous_hash)

        status = "OK" if recomputed == row["entry_hash"] else "TAMPERED"

        results.append({
            "log_id":          int(row["id"]),
            "stored_hash":     row["entry_hash"],
            "recomputed_hash": recomputed,
            "status":          status,
        })

        # IMPORTANT: always advance using the STORED hash (not recomputed),
        # so the chain verification faithfully reflects how the hashes were
        # originally calculated — mismatches propagate from the tampered row.
        previous_hash = row["entry_hash"]

    return results


def repair_chain() -> int:
    """
    Recompute and update legitimate hashes across all rows sequentially from the current raw_entry values.
    Returns the number of rows updated.
    """
    conn = database._get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, raw_entry FROM logs ORDER BY id ASC")
    db_rows = cursor.fetchall()
    previous_hash = ""
    repaired_count = 0
    for r in db_rows:
        new_hash = compute_hash(r["raw_entry"], previous_hash)
        cursor.execute("UPDATE logs SET entry_hash = ? WHERE id = ?", (new_hash, r["id"]))
        previous_hash = new_hash
        repaired_count += 1
    conn.commit()
    conn.close()
    return repaired_count


# ---------------------------------------------------------------------------
# Self-test (run `python hash_chain.py` directly to verify)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    # Start fresh so the test is repeatable
    if os.path.exists("logs.db"):
        os.remove("logs.db")

    database.init_db()
    print("[hash_chain.py] Self-test starting on a clean DB ...\n")

    # --- Part A: insert three entries and verify all are OK ----------------
    id1 = add_log_entry("2024-01-15 09:00:00", "alice", "192.168.1.10", "login_success")
    id2 = add_log_entry("2024-01-15 09:01:00", "bob",   "192.168.1.11", "login_success")
    id3 = add_log_entry("2024-01-15 09:02:00", "carol", "192.168.1.12", "login_failed")
    print(f"Inserted 3 entries with ids: {id1}, {id2}, {id3}")

    results = verify_chain()
    print("\n-- verify_chain() after clean inserts --")
    for r in results:
        print(f"  row {r['log_id']:>2} | status = {r['status']}")

    all_ok = all(r["status"] == "OK" for r in results)
    assert all_ok, "Expected all rows to be OK before tampering!"
    print("  -> All rows OK (PASSED)\n")

    # --- Part B: tamper with row 2 and verify the chain breaks -------------
    # update_raw_entry changes raw_entry but leaves entry_hash intact.
    # This means row 2's recomputed hash will NOT match its stored hash -> TAMPERED.
    # Row 3 chains from row 2's stored hash (which is unchanged), so it still
    # verifies as OK — exactly row 2 is the detected tamper point.
    database.update_raw_entry(id2, "INJECTED_FAKE_DATA")
    print(f"Tampered row {id2} raw_entry -> 'INJECTED_FAKE_DATA'")

    results_after = verify_chain()
    print("\n-- verify_chain() after tampering row 2 --")
    for r in results_after:
        print(f"  row {r['log_id']:>2} | status = {r['status']}")

    # Exactly row 2 should be TAMPERED; rows before and after remain OK
    # (they chain from the unchanged stored hashes).
    row1_ok    = results_after[0]["status"] == "OK"
    row2_bad   = results_after[1]["status"] == "TAMPERED"
    row3_ok    = results_after[2]["status"] == "OK"   # still valid chain from stored hash
    assert row1_ok,  "Row 1 should still be OK (it was not tampered)"
    assert row2_bad, "Row 2 should be TAMPERED (raw_entry modified without updating hash)"
    assert row3_ok,  "Row 3 chains from row 2 stored hash (unchanged) -> still OK"
    print("\n  -> Exactly row 2 flagged as TAMPERED (PASSED)")

    print("\n[hash_chain.py] All checks PASSED")
