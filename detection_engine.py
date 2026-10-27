"""
detection_engine.py — Rule-based + statistical anomaly detection.

No ML libraries used. Detection is purely:
  1. Rule-based checks  (check_rules)
  2. Z-score statistics (compute_zscore)
  3. Shannon entropy    (shannon_entropy)
  4. Severity classification (classify_severity)

The engine is stateless — callers pass in the current row and any rolling
window data needed for rules / Z-score; nothing is stored here.
"""

import math
import pandas as pd
from datetime import datetime


# ---------------------------------------------------------------------------
# BLACKLIST: IPs that are always suspicious regardless of other factors.
# These must overlap with some IPs in sample_dataset.csv so the demo fires.
# ---------------------------------------------------------------------------

BLACKLIST: list[str] = [
    "203.0.113.5",
    "198.51.100.23",
]


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """
    Compute the Shannon entropy of `text` in bits.

    A string of identical characters (e.g. "aaaa") has entropy ~0.
    A highly varied string (e.g. "aB3$kZ9!") has much higher entropy.

    Formula: H = -sum( p(c) * log2(p(c)) )  for each unique character c

    Parameters
    ----------
    text : str  — the input string to measure

    Returns
    -------
    float  — entropy in bits; 0.0 if text is empty
    """
    if not text:
        return 0.0

    total_chars = len(text)
    # Count occurrences of each unique character
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    # Compute H = -sum( p * log2(p) )
    entropy = 0.0
    for count in freq.values():
        p = count / total_chars
        entropy -= p * math.log2(p)

    return entropy


# ---------------------------------------------------------------------------
# check_rules
# ---------------------------------------------------------------------------

def check_rules(current_row: dict, recent_rows: pd.DataFrame) -> list:
    """
    Apply hard-coded security rules to one log entry and return a list of
    triggered rule names.

    Rules
    -----
    1. failed_login_burst
       If the same username has > 5 login_failed events within the last 60 s
       of current_row's timestamp (in recent_rows), flag a brute-force burst.

    2. blacklisted_ip
       If current_row's source_ip appears in the BLACKLIST constant above.

    3. off_hours
       If the event's hour is before 09:00 or after 21:00 (local time).

    Parameters
    ----------
    current_row  : dict with keys timestamp, username, source_ip, event_type
    recent_rows  : pd.DataFrame of recently processed rows used as the
                   rolling window (columns: timestamp, username, event_type, ...)

    Returns
    -------
    list[str]  — names of triggered rules; empty list means no anomaly
    """
    triggered = []

    # Parse the current row's timestamp once — used by rules 1 and 3
    try:
        current_ts = pd.to_datetime(current_row["timestamp"])
    except Exception:
        # If timestamp is unparseable, skip time-based rules gracefully
        current_ts = None

    # ------------------------------------------------------------------
    # Rule 1: failed_login_burst
    # Count failed logins from the same username within the last 60 seconds
    # ------------------------------------------------------------------
    if current_ts is not None and not recent_rows.empty:
        try:
            # Ensure timestamps in recent_rows are datetime objects
            recent_rows_copy = recent_rows.copy()
            recent_rows_copy["timestamp"] = pd.to_datetime(
                recent_rows_copy["timestamp"], errors="coerce"
            )

            window_start = current_ts - pd.Timedelta(seconds=60)

            burst_mask = (
                (recent_rows_copy["username"] == current_row["username"])
                & (recent_rows_copy["event_type"] == "login_failed")
                & (recent_rows_copy["timestamp"] >= window_start)
                & (recent_rows_copy["timestamp"] <= current_ts)
            )
            failed_count = burst_mask.sum()

            if failed_count > 5:
                triggered.append("failed_login_burst")
        except Exception:
            pass  # skip rule if data is malformed

    # ------------------------------------------------------------------
    # Rule 2: blacklisted_ip
    # ------------------------------------------------------------------
    if current_row.get("source_ip", "") in BLACKLIST:
        triggered.append("blacklisted_ip")

    # ------------------------------------------------------------------
    # Rule 3: off_hours  (before 09:00 or after 21:00)
    # ------------------------------------------------------------------
    if current_ts is not None:
        hour = current_ts.hour
        if hour < 9 or hour > 21:
            triggered.append("off_hours")

    return triggered


# ---------------------------------------------------------------------------
# compute_zscore
# ---------------------------------------------------------------------------

def compute_zscore(recent_values: pd.Series, new_value: float) -> float:
    """
    Compute how many standard deviations `new_value` is from the mean of
    `recent_values`.

    Returns 0.0 if:
      - fewer than 5 historical values exist (not enough baseline history)
      - the standard deviation of recent values is 0 (avoid divide-by-zero)

    Parameters
    ----------
    recent_values : pd.Series of float — historical window (e.g. events/minute)
    new_value     : float — the latest measurement to score

    Returns
    -------
    float  — Z-score; values with |z| > 3 are statistically unusual
    """
    if len(recent_values) < 5:
        return 0.0  # not enough history yet

    mean = recent_values.mean()
    std  = recent_values.std()

    if std == 0:
        return 0.0  # all historical values are identical — avoid divide-by-zero

    return (new_value - mean) / std


# ---------------------------------------------------------------------------
# classify_severity
# ---------------------------------------------------------------------------

def classify_severity(
    rule_hits: list,
    z_score: float,
    tampering: bool = False,
) -> str:
    """
    Determine the severity level of an event based on detection signals.

    Priority order (highest wins):
      High   — tampering detected, OR (rule hit AND |z| > 3)
      Medium — any rule hit, OR |z| > 3
      Low    — 2 < |z| <= 3
      None   — no signals

    Parameters
    ----------
    rule_hits : list of triggered rule names (from check_rules)
    z_score   : float from compute_zscore
    tampering : bool — True if hash-chain verification failed for this entry

    Returns
    -------
    str  — "High" | "Medium" | "Low" | "None"
    """
    abs_z = abs(z_score)

    if tampering:
        return "High"

    if rule_hits and abs_z > 3:
        return "High"

    if rule_hits or abs_z > 3:
        return "Medium"

    if 2 < abs_z <= 3:
        return "Low"

    return "None"


# ---------------------------------------------------------------------------
# Self-test (run `python detection_engine.py` directly to verify)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[detection_engine.py] Running self-test ...\n")

    # --- Shannon entropy test -----------------------------------------------
    e_uniform = shannon_entropy("aaaa")
    e_varied  = shannon_entropy("aB3$kZ9!")
    print(f"  shannon_entropy('aaaa')     = {e_uniform:.4f}  (expect ~0)")
    print(f"  shannon_entropy('aB3$kZ9!') = {e_varied:.4f}  (expect noticeably higher)")
    assert e_uniform < 0.001, "Uniform string should have entropy ~0"
    assert e_varied > 2.0,    "High-variety string should have entropy > 2 bits"
    print("  -> Shannon entropy test PASSED\n")

    # --- check_rules: blacklisted IP ----------------------------------------
    row_blacklist = {
        "timestamp": "2024-01-15 10:30:00",
        "username": "alice",
        "source_ip": "203.0.113.5",   # in BLACKLIST
        "event_type": "login_success",
    }
    hits = check_rules(row_blacklist, pd.DataFrame())
    assert "blacklisted_ip" in hits, "Should flag blacklisted IP"
    print(f"  blacklisted_ip rule hit  -> {hits}  (PASSED)")

    # --- check_rules: off_hours ---------------------------------------------
    row_offhours = {
        "timestamp": "2024-01-15 02:00:00",  # 2 AM
        "username": "bob",
        "source_ip": "10.0.0.1",
        "event_type": "login_success",
    }
    hits2 = check_rules(row_offhours, pd.DataFrame())
    assert "off_hours" in hits2, "Should flag off-hours login"
    print(f"  off_hours rule hit       -> {hits2}  (PASSED)")

    # --- check_rules: failed_login_burst ------------------------------------
    import numpy as np
    from datetime import timedelta

    base_time = datetime(2024, 1, 15, 10, 0, 0)
    # Build 6 failed logins within 60 seconds for user "eve"
    recent_data = pd.DataFrame({
        "timestamp": [(base_time + timedelta(seconds=i)).isoformat(sep=" ")
                      for i in range(6)],
        "username":   ["eve"] * 6,
        "event_type": ["login_failed"] * 6,
        "source_ip":  ["10.0.0.5"] * 6,
    })
    row_burst = {
        "timestamp":  (base_time + timedelta(seconds=10)).isoformat(sep=" "),
        "username":   "eve",
        "source_ip":  "10.0.0.5",
        "event_type": "login_failed",
    }
    hits3 = check_rules(row_burst, recent_data)
    assert "failed_login_burst" in hits3, "Should flag login burst"
    print(f"  failed_login_burst hit   -> {hits3}  (PASSED)")

    # --- Z-score test -------------------------------------------------------
    history = pd.Series([10.0, 11.0, 10.5, 9.8, 10.2, 10.1])
    z_normal  = compute_zscore(history, 10.3)  # within normal range
    z_extreme = compute_zscore(history, 50.0)  # way outside normal range
    print(f"\n  compute_zscore (normal)  = {z_normal:.2f}  (expect near 0)")
    print(f"  compute_zscore (extreme) = {z_extreme:.2f}  (expect large positive)")
    assert abs(z_normal) < 1.0,   "Normal value should have low Z-score"
    assert z_extreme > 10.0,      "Extreme value should have high Z-score"
    print("  -> Z-score test PASSED\n")

    # --- classify_severity --------------------------------------------------
    assert classify_severity([], 0.0, tampering=True) == "High"
    assert classify_severity(["off_hours"], 4.0)       == "High"
    assert classify_severity(["off_hours"], 0.5)       == "Medium"
    assert classify_severity([], 4.0)                  == "Medium"
    assert classify_severity([], 2.5)                  == "Low"
    assert classify_severity([], 0.5)                  == "None"
    print("  classify_severity tests  -> all PASSED")

    print("\n[detection_engine.py] All checks PASSED")
