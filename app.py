"""
app.py — SOC Security Log Analyzer & Anomaly Detector
Enterprise Security Operations Center Dashboard & Cryptographic Audit Station

Features:
  1. Ingestion & Threat Analysis — Structured CSV ingestion, live telemetry analytics, threat vector distributions.
  2. Attack Simulation & Threat Emulation — Controlled authentication threat generation with standard scenario presets.
  3. Security Alerts & Incident Queue — Triage queue with multi-factor filtering, severity tagging, and mitigation guidance.
  4. Cryptographic Ledger Integrity — SHA-256 blockchain-style hash chain verification and tamper forensics.

Engine: Stateless deterministic rules, statistical Z-score outlier detection, Shannon entropy profiling. Zero ML overhead.
"""

import os
import io
import math
import time
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import streamlit as st

# Local persistence and detection modules
import database
import hash_chain
import detection_engine


# ---------------------------------------------------------------------------
# Pandas Styler compatibility helper
# ---------------------------------------------------------------------------

def _apply_style_map(styler, func, subset=None):
    """Safely apply an elementwise styling function across pandas versions."""
    if hasattr(styler, "map"):
        return styler.map(func, subset=subset)
    return styler.applymap(func, subset=subset)


# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Security Log Analyzer & Anomaly Detector",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize database schema if not present
database.init_db()


# ---------------------------------------------------------------------------
# Enterprise SOC Design System (CSS)
# ---------------------------------------------------------------------------

st.markdown("""
<style>
  /* Base fonts: Inter for clean UI hierarchy, JetBrains Mono for technical artifacts */
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

  html, body, [class*="css"], .stApp {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background-color: #0b0f17;
      color: #e2e8f0;
  }

  /* Monospace utility for hashes, IPs, log IDs, and timestamps */
  .mono, .hash-mono {
      font-family: 'JetBrains Mono', 'SFMono-Regular', Menlo, Monaco, Consolas, monospace !important;
  }

  /* Sidebar styling: fixed width and enterprise dark border */
  section[data-testid="stSidebar"] {
      min-width: 320px !important;
      max-width: 320px !important;
      background-color: #080c14 !important;
      border-right: 1px solid #1e293b !important;
  }

  section[data-testid="stSidebar"] > div {
      padding-top: 1.5rem !important;
      padding-bottom: 2rem !important;
  }

  /* Main container padding */
  .main .block-container {
      padding-top: 1.25rem !important;
      padding-bottom: 3rem !important;
      max-width: 1400px;
  }

  /* Header bar: flat, dark, clean, professional */
  .soc-header {
      background-color: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 1.2rem 1.6rem;
      margin-bottom: 1.5rem;
  }

  .soc-header-inner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
  }

  .soc-title {
      font-size: 1.25rem;
      font-weight: 700;
      color: #f8fafc;
      letter-spacing: -0.01em;
      margin: 0;
      line-height: 1.3;
  }

  .soc-subtitle {
      font-size: 0.82rem;
      color: #94a3b8;
      margin-top: 0.25rem;
  }

  /* Status tag in header */
  .threat-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.35rem 0.75rem;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.76rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      border: 1px solid;
  }

  .threat-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background-color: currentColor;
  }

  .tag-nominal {
      background-color: rgba(16, 185, 129, 0.08);
      border-color: rgba(16, 185, 129, 0.3);
      color: #10b981;
  }

  .tag-elevated {
      background-color: rgba(245, 158, 11, 0.08);
      border-color: rgba(245, 158, 11, 0.3);
      color: #f59e0b;
  }

  .tag-critical {
      background-color: rgba(239, 68, 68, 0.08);
      border-color: rgba(239, 68, 68, 0.3);
      color: #ef4444;
  }

  /* Tabs: underline-style active tab, flat and clean */
  div[data-testid="stTabs"] {
      border-bottom: 1px solid #1e293b;
      margin-bottom: 1.25rem;
  }

  div[data-testid="stTabs"] button {
      background: transparent !important;
      border: none !important;
      border-bottom: 2px solid transparent !important;
      border-radius: 0 !important;
      color: #94a3b8 !important;
      font-size: 0.88rem !important;
      font-weight: 500 !important;
      padding: 0.65rem 1.2rem !important;
      box-shadow: none !important;
      transition: all 0.15s ease !important;
  }

  div[data-testid="stTabs"] button:hover {
      color: #f8fafc !important;
  }

  div[data-testid="stTabs"] button[aria-selected="true"] {
      color: #2563eb !important;
      border-bottom: 2px solid #2563eb !important;
      font-weight: 600 !important;
  }

  /* KPI Summary Metric Cards */
  .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.75rem;
      margin-bottom: 1.25rem;
  }

  .kpi-card {
      background-color: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 0.85rem 1.1rem;
  }

  .kpi-label {
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #64748b;
      margin-bottom: 0.25rem;
  }

  .kpi-value {
      font-size: 1.65rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      color: #f8fafc;
      line-height: 1.2;
  }

  .kpi-subtext {
      font-size: 0.74rem;
      color: #94a3b8;
      margin-top: 0.2rem;
  }

  /* Section Headings with subtle bottom border */
  .soc-section-heading {
      font-size: 0.96rem;
      font-weight: 600;
      color: #f8fafc;
      padding-bottom: 0.45rem;
      border-bottom: 1px solid #1e293b;
      margin: 1.5rem 0 0.85rem 0;
  }

  .soc-section-desc {
      font-size: 0.8rem;
      color: #64748b;
      margin-top: -0.45rem;
      margin-bottom: 1rem;
  }

  /* Sidebar Detection Rule Rows */
  .rule-list {
      display: flex;
      flex-direction: column;
      gap: 0.45rem;
      margin-top: 0.5rem;
  }

  .rule-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background-color: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 4px;
      padding: 0.45rem 0.65rem;
      font-size: 0.78rem;
  }

  .rule-info {
      display: flex;
      flex-direction: column;
  }

  .rule-name {
      font-weight: 600;
      color: #e2e8f0;
  }

  .rule-desc {
      font-size: 0.72rem;
      color: #64748b;
  }

  .rule-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.68rem;
      font-weight: 600;
      padding: 0.15rem 0.4rem;
      border-radius: 3px;
      letter-spacing: 0.03em;
  }

  .tag-sev-high {
      background-color: rgba(239, 68, 68, 0.1);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
  }

  .tag-sev-med {
      background-color: rgba(245, 158, 11, 0.1);
      color: #f59e0b;
      border: 1px solid rgba(245, 158, 11, 0.3);
  }

  .tag-sev-low {
      background-color: rgba(16, 185, 129, 0.1);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.3);
  }

  /* Button styling: High-contrast, tactile enterprise buttons */

  /* 1. Base / Standard / Action Buttons (Scenario Presets, Filters, Secondary Actions) */
  div[data-testid="stButton"] button,
  div[data-testid="stButton"] > button,
  button[data-testid*="secondary"],
  button[kind*="secondary"],
  button[data-testid="stBaseButton-secondary"],
  .stButton > button {
      background-color: #162032 !important;
      background: #162032 !important;
      color: #f8fafc !important;
      border: 1px solid #2d3e58 !important;
      border-radius: 6px !important;
      font-weight: 500 !important;
      font-size: 0.85rem !important;
      padding: 0.6rem 0.95rem !important;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3) !important;
      cursor: pointer !important;
      transition: all 0.15s ease-in-out !important;
  }

  div[data-testid="stButton"] button:hover,
  div[data-testid="stButton"] > button:hover,
  button[data-testid*="secondary"]:hover,
  button[kind*="secondary"]:hover,
  button[data-testid="stBaseButton-secondary"]:hover,
  .stButton > button:hover {
      background-color: #22324f !important;
      background: #22324f !important;
      border-color: #3b82f6 !important;
      color: #ffffff !important;
      box-shadow: 0 0 10px rgba(59, 130, 246, 0.25) !important;
      transform: translateY(-1px);
  }

  /* 2. Primary Action Buttons & Form Submit Buttons */
  div[data-testid="stButton"] button[kind="primary"],
  div[data-testid="stButton"] button[data-testid="stBaseButton-primary"],
  div[data-testid="stFormSubmitButton"] button,
  div[data-testid="stFormSubmitButton"] > button,
  button[kind="primaryFormSubmit"],
  button[data-testid="stBaseButton-primaryFormSubmit"],
  button[kind="primary"],
  button[data-testid="stBaseButton-primary"],
  .stFormSubmitButton > button {
      background-color: #2563eb !important;
      background: #2563eb !important;
      color: #ffffff !important;
      border: 1px solid #3b82f6 !important;
      border-radius: 6px !important;
      font-weight: 600 !important;
      font-size: 0.88rem !important;
      padding: 0.7rem 1.4rem !important;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4) !important;
      cursor: pointer !important;
      transition: all 0.15s ease-in-out !important;
  }

  div[data-testid="stButton"] button[kind="primary"]:hover,
  div[data-testid="stButton"] button[data-testid="stBaseButton-primary"]:hover,
  div[data-testid="stFormSubmitButton"] button:hover,
  div[data-testid="stFormSubmitButton"] > button:hover,
  button[kind="primaryFormSubmit"]:hover,
  button[data-testid="stBaseButton-primaryFormSubmit"]:hover,
  button[kind="primary"]:hover,
  button[data-testid="stBaseButton-primary"]:hover,
  .stFormSubmitButton > button:hover {
      background-color: #1d4ed8 !important;
      background: #1d4ed8 !important;
      border-color: #60a5fa !important;
      color: #ffffff !important;
      box-shadow: 0 0 14px rgba(37, 99, 235, 0.45) !important;
      transform: translateY(-1px);
  }

  /* Force inner text and icons to inherit bright text colors */
  div[data-testid="stButton"] button p,
  div[data-testid="stButton"] button span,
  div[data-testid="stButton"] button div,
  div[data-testid="stFormSubmitButton"] button p,
  div[data-testid="stFormSubmitButton"] button span,
  div[data-testid="stFormSubmitButton"] button div {
      color: inherit !important;
      font-weight: inherit !important;
      font-size: inherit !important;
  }

  /* Flat Hash Chain Flow Diagram */
  .chain-diagram-container {
      background-color: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 0.9rem 1.2rem;
      margin-bottom: 1.25rem;
  }

  .chain-diagram-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      overflow-x: auto;
  }

  .chain-block-node {
      flex: 1;
      background-color: #080c14;
      border: 1px solid #1e293b;
      border-radius: 4px;
      padding: 0.65rem 0.85rem;
  }

  .chain-node-title {
      font-size: 0.75rem;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.04em;
  }

  .chain-node-formula {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #e2e8f0;
      margin-top: 0.2rem;
  }

  .chain-arrow {
      color: #475569;
      font-size: 1.1rem;
      font-weight: 600;
      padding: 0 0.25rem;
  }

  /* Concise Audit Summary Box */
  .audit-summary-box {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      background-color: #0d121f;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 0.75rem 1rem;
      margin-bottom: 1rem;
      font-size: 0.86rem;
  }

  .audit-summary-box.audit-valid {
      border-left: 3px solid #10b981;
  }

  .audit-summary-box.audit-tampered {
      border-left: 3px solid #ef4444;
  }

  /* Result Verdict Card */
  .verdict-box {
      border-radius: 6px;
      padding: 0.9rem 1.1rem;
      margin-top: 1rem;
      background-color: #0d121f;
      border: 1px solid #1e293b;
  }

  .verdict-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
  }

  .verdict-title {
      font-size: 0.92rem;
      font-weight: 600;
  }

  /* Dataframe borders and rounding */
  div[data-testid="stDataFrame"] {
      border: 1px solid #1e293b;
      border-radius: 6px;
      overflow: hidden;
  }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar: Console Controls & Active Detection Rules
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Console Controls")
    st.caption("Active Defense & Audit Station")

    sample_csv_path = os.path.join("data", "sample_dataset.csv")
    sample_available = os.path.exists(sample_csv_path)

    if st.button("Load Demo Dataset (151 Logs)", use_container_width=True, type="primary"):
        if sample_available:
            with st.spinner("Ingesting log stream and calculating cryptographic chain..."):
                sample_df = pd.read_csv(sample_csv_path)
                processed_window = []
                for _, row in sample_df.iterrows():
                    c_row = {
                        "timestamp": str(row["timestamp"]).strip(),
                        "username": str(row["username"]).strip(),
                        "source_ip": str(row["source_ip"]).strip(),
                        "event_type": str(row["event_type"]).strip(),
                    }
                    log_id = hash_chain.add_log_entry(
                        timestamp=c_row["timestamp"],
                        username=c_row["username"],
                        source_ip=c_row["source_ip"],
                        event_type=c_row["event_type"],
                    )
                    w_df = pd.DataFrame(processed_window[-20:]) if processed_window else pd.DataFrame()
                    hits = detection_engine.check_rules(c_row, w_df)
                    recent_c = pd.Series([1] * len(w_df)) if not w_df.empty else pd.Series([], dtype=float)
                    z = detection_engine.compute_zscore(recent_c, 1.0)
                    sev = detection_engine.classify_severity(hits, z)
                    if sev != "None":
                        for reason in hits:
                            database.insert_alert(log_id=log_id, reason=reason, severity=sev)
                        if not hits and abs(z) > 2:
                            database.insert_alert(log_id=log_id, reason="z_score_anomaly", severity=sev)
                    processed_window.append(c_row)
                st.toast("Ingested 151 log entries successfully.")
                st.rerun()
        else:
            st.error("Sample dataset file not found at data/sample_dataset.csv.")

    st.markdown("---")

    st.markdown("#### Active Detection Rules")
    st.markdown("""
    <div class="rule-list">
      <div class="rule-row">
        <div class="rule-info">
          <span class="rule-name">Failed Login Burst</span>
          <span class="rule-desc">&ge; 5 failed logins within 60s</span>
        </div>
        <span class="rule-tag tag-sev-high">HIGH</span>
      </div>
      <div class="rule-row">
        <div class="rule-info">
          <span class="rule-name">Blacklisted IP</span>
          <span class="rule-desc">Known malicious threat actor IP</span>
        </div>
        <span class="rule-tag tag-sev-high">HIGH</span>
      </div>
      <div class="rule-row">
        <div class="rule-info">
          <span class="rule-name">Off-Hours Access</span>
          <span class="rule-desc">Logins between 21:00 and 09:00</span>
        </div>
        <span class="rule-tag tag-sev-med">MEDIUM</span>
      </div>
      <div class="rule-row">
        <div class="rule-info">
          <span class="rule-name">High-Entropy User</span>
          <span class="rule-desc">Shannon entropy &ge; 3.0 bits</span>
        </div>
        <span class="rule-tag tag-sev-med">MEDIUM</span>
      </div>
      <div class="rule-row">
        <div class="rule-info">
          <span class="rule-name">Z-Score Outlier</span>
          <span class="rule-desc">Statistical volume spike (|Z| &gt; 2)</span>
        </div>
        <span class="rule-tag tag-sev-low">LOW</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("#### Database Administration")
    if st.button("Reset & Purge All Logs", use_container_width=True):
        database.reset_db()
        st.toast("Database reset to clean state.")
        st.rerun()

    st.markdown("---")
    st.caption("Engine: Deterministic Rules + Z-Score · SHA-256 Ledger")


# ---------------------------------------------------------------------------
# Global Header & Live Threat Level Status
# ---------------------------------------------------------------------------

df_all_logs = database.get_all_logs()
df_all_alerts = database.get_all_alerts()

total_logs_count = len(df_all_logs)
total_alerts_count = len(df_all_alerts)
high_alerts_count = int((df_all_alerts["severity"] == "High").sum()) if not df_all_alerts.empty else 0
med_alerts_count = int((df_all_alerts["severity"] == "Medium").sum()) if not df_all_alerts.empty else 0
low_alerts_count = int((df_all_alerts["severity"] == "Low").sum()) if not df_all_alerts.empty else 0

# Threat Level determination driven by real alert state
if high_alerts_count > 5:
    threat_status = "CRITICAL"
    threat_tag_class = "tag-critical"
elif high_alerts_count > 0 or med_alerts_count > 3:
    threat_status = "ELEVATED"
    threat_tag_class = "tag-elevated"
else:
    threat_status = "NOMINAL"
    threat_tag_class = "tag-nominal"

st.markdown(f"""
<div class="soc-header">
  <div class="soc-header-inner">
    <div>
      <h1 class="soc-title">SOC Security Log Analyzer & Anomaly Detector</h1>
      <div class="soc-subtitle">Cryptographic SHA-256 tamper-evident hash chaining and deterministic anomaly detection</div>
    </div>
    <div class="threat-tag {threat_tag_class}">
      <span class="threat-dot"></span>
      <span>THREAT LEVEL: {threat_status}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Main Application Tabs
# ---------------------------------------------------------------------------

tab1, tab2, tab3, tab4 = st.tabs([
    ":material/upload_file: Ingestion",
    ":material/terminal: Attack Simulation",
    ":material/warning: Alerts",
    ":material/verified_user: Integrity Verification",
])


# ===========================================================================
# TAB 1 — Ingestion
# ===========================================================================

with tab1:
    st.markdown('<div class="soc-section-heading">Log Ingestion & Forensic Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Ingest structured login events, compute cryptographic SHA-256 proof hashes, and evaluate threat vectors.</div>', unsafe_allow_html=True)

    col_up1, col_up2 = st.columns([3, 2])

    with col_up1:
        uploaded_file = st.file_uploader(
            "Upload Custom Login CSV Log File",
            type=["csv"],
            help="Expected schema: timestamp, username, source_ip, event_type",
            key="custom_csv_uploader",
        )

    with col_up2:
        st.markdown("**Quick Demo Dataset**")
        st.caption("Pre-packaged authentication telemetry with normal access, bursts, off-hours, and blacklisted IPs.")
        if st.button("Ingest 'sample_dataset.csv' (151 Events)", use_container_width=True):
            if os.path.exists(sample_csv_path):
                uploaded_file = "sample_dataset"
            else:
                st.error("Sample dataset file missing at data/sample_dataset.csv.")

    # Process either uploaded file or triggered sample
    to_process_df = None
    if uploaded_file is not None:
        if isinstance(uploaded_file, str) and uploaded_file == "sample_dataset":
            to_process_df = pd.read_csv(sample_csv_path)
        else:
            try:
                to_process_df = pd.read_csv(uploaded_file)
            except Exception as e:
                st.error(f"Failed to read CSV: {e}")

    if to_process_df is not None:
        required_cols = {"timestamp", "username", "source_ip", "event_type"}
        missing = required_cols - set(to_process_df.columns)
        if missing:
            st.error(f"CSV missing mandatory columns: {', '.join(sorted(missing))}")
        else:
            if len(to_process_df) > 2000:
                st.warning(f"File contains {len(to_process_df):,} rows. Ingesting first 2,000 rows for responsive processing.")
                to_process_df = to_process_df.head(2000)

            total_rows = len(to_process_df)
            prog_bar = st.progress(0, text="Initializing cryptographic engine...")

            results_rows = []
            processed_window = []
            start_time = time.time()

            for idx, row in to_process_df.iterrows():
                current_row = {
                    "timestamp": str(row["timestamp"]).strip(),
                    "username": str(row["username"]).strip(),
                    "source_ip": str(row["source_ip"]).strip(),
                    "event_type": str(row["event_type"]).strip(),
                }

                log_id = hash_chain.add_log_entry(
                    timestamp=current_row["timestamp"],
                    username=current_row["username"],
                    source_ip=current_row["source_ip"],
                    event_type=current_row["event_type"],
                )

                window_df = pd.DataFrame(processed_window[-20:]) if processed_window else pd.DataFrame()
                rule_hits = detection_engine.check_rules(current_row, window_df)

                recent_counts = pd.Series([1] * len(window_df)) if not window_df.empty else pd.Series([], dtype=float)
                z = detection_engine.compute_zscore(recent_counts, 1.0)
                entropy_val = detection_engine.shannon_entropy(current_row["username"])
                severity = detection_engine.classify_severity(rule_hits, z)

                if severity != "None":
                    for reason in rule_hits:
                        database.insert_alert(log_id=log_id, reason=reason, severity=severity)
                    if not rule_hits and abs(z) > 2:
                        database.insert_alert(log_id=log_id, reason="z_score_anomaly", severity=severity)

                results_rows.append({
                    "log_id": log_id,
                    "timestamp": current_row["timestamp"],
                    "username": current_row["username"],
                    "source_ip": current_row["source_ip"],
                    "event_type": current_row["event_type"],
                    "rules_hit": ", ".join(rule_hits) if rule_hits else "None",
                    "z_score": round(z, 2),
                    "entropy": round(entropy_val, 2),
                    "severity": severity,
                })
                processed_window.append(current_row)

                pct = (idx - to_process_df.index[0] + 1) / total_rows
                prog_bar.progress(pct, text=f"Processing row {idx + 1} of {total_rows}...")

            elapsed = round(time.time() - start_time, 2)
            prog_bar.progress(1.0, text=f"Analysis complete: {total_rows} entries processed in {elapsed}s.")
            st.session_state["latest_results"] = results_rows

    st.markdown("---")

    # Ingestion & Analytics Display
    df_all_logs = database.get_all_logs()
    df_all_alerts = database.get_all_alerts()

    if df_all_logs.empty:
        st.info("No log records found in database. Load demo dataset from sidebar or upload a CSV log file.")
    else:
        total_ev = len(df_all_logs)
        high_sev = int((df_all_alerts["severity"] == "High").sum()) if not df_all_alerts.empty else 0
        med_sev = int((df_all_alerts["severity"] == "Medium").sum()) if not df_all_alerts.empty else 0
        fail_ev = int((df_all_logs["event_type"] == "login_failed").sum())
        fail_rate = round((fail_ev / total_ev) * 100, 1) if total_ev > 0 else 0
        unique_ips = int(df_all_logs["source_ip"].nunique())

        # Top summary KPI metric cards row
        st.markdown(f"""
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Total Events</div>
            <div class="kpi-value">{total_ev:,}</div>
            <div class="kpi-subtext">Chained log entries</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">High Severity Threats</div>
            <div class="kpi-value" style="color:#ef4444">{high_sev}</div>
            <div class="kpi-subtext">Bursts & blacklisted IPs</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Medium Anomalies</div>
            <div class="kpi-value" style="color:#f59e0b">{med_sev}</div>
            <div class="kpi-subtext">Off-hours & high entropy</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Failed Logins</div>
            <div class="kpi-value">{fail_ev}</div>
            <div class="kpi-subtext">{fail_rate}% failure rate</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Unique Source IPs</div>
            <div class="kpi-value">{unique_ips}</div>
            <div class="kpi-subtext">Active endpoints</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # Threat Intelligence Charts Section (Using single muted blue accent color)
        st.markdown('<div class="soc-section-heading">Threat Intelligence & Anomaly Visualization</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-section-desc">Aggregate authentication telemetry and anomaly distribution.</div>', unsafe_allow_html=True)

        ch_col1, ch_col2 = st.columns([3, 2])

        with ch_col1:
            try:
                df_ts = df_all_logs.copy()
                df_ts["ts_dt"] = pd.to_datetime(df_ts["timestamp"], errors="coerce")
                df_ts = df_ts.dropna(subset=["ts_dt"]).sort_values("ts_dt")

                if not df_ts.empty:
                    span_seconds = (df_ts["ts_dt"].max() - df_ts["ts_dt"].min()).total_seconds()
                    if span_seconds > 30 * 86400:
                        unit_label = "Daily"
                        timeline_series = df_ts.groupby(df_ts["ts_dt"].dt.strftime("%Y-%m-%d"))["id"].count()
                    elif span_seconds > 86400:
                        unit_label = "Hourly"
                        timeline_series = df_ts.groupby(df_ts["ts_dt"].dt.strftime("%Y-%m-%d %H:00"))["id"].count()
                    elif span_seconds > 3600:
                        unit_label = "10-Min"
                        timeline_series = df_ts.groupby(df_ts["ts_dt"].dt.strftime("%H:%M"))["id"].count()
                    else:
                        unit_label = "Per-Minute"
                        timeline_series = df_ts.groupby(df_ts["ts_dt"].dt.strftime("%H:%M:%S"))["id"].count()

                    if len(timeline_series) > 100:
                        timeline_series = timeline_series.tail(100)

                    timeline_df = pd.DataFrame({
                        "Time Interval": timeline_series.index,
                        "Events Volume": timeline_series.values
                    }).set_index("Time Interval")

                    st.markdown(f"**Event Activity Timeline ({unit_label} Volume)**")
                    st.line_chart(timeline_df, color="#3b82f6", height=230)
                else:
                    st.caption("Insufficient timestamp data for timeline.")
            except Exception as e:
                st.caption(f"Could not build timeline: {e}")

        with ch_col2:
            st.markdown("**Threat Vectors Breakdown (Triggered Rules)**")
            if not df_all_alerts.empty:
                rule_breakdown = df_all_alerts["reason"].value_counts()
                rule_df = pd.DataFrame({"Reason": rule_breakdown.index, "Alert Count": rule_breakdown.values}).set_index("Reason")
                st.bar_chart(rule_df, color="#3b82f6", height=230)
            else:
                st.caption("No rule-based alerts triggered yet.")

        col_sub1, col_sub2 = st.columns(2)
        with col_sub1:
            st.markdown("**Top Targeted User Accounts**")
            top_users = df_all_logs["username"].value_counts().head(7)
            top_users_df = pd.DataFrame({"User": top_users.index, "Logins": top_users.values}).set_index("User")
            st.bar_chart(top_users_df, color="#3b82f6", height=190)

        with col_sub2:
            st.markdown("**Top Source IP Addresses**")
            top_ips = df_all_logs["source_ip"].value_counts().head(7)
            top_ips_df = pd.DataFrame({"IP": top_ips.index, "Requests": top_ips.values}).set_index("IP")
            st.bar_chart(top_ips_df, color="#3b82f6", height=190)

        # Detailed Log Records Explorer
        st.markdown('<div class="soc-section-heading">Forensic Ingested Logs Explorer</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-section-desc">Search, filter, and inspect ingested authentication records.</div>', unsafe_allow_html=True)

        f_col1, f_col2, f_col3 = st.columns([2, 2, 3])
        with f_col1:
            event_filter = st.selectbox("Filter Event Type", ["All Events", "login_failed", "login_success"], key="tab1_event_filter")
        with f_col2:
            user_filter = st.selectbox("Filter by Username", ["All Users"] + sorted(df_all_logs["username"].unique().tolist()), key="tab1_user_filter")
        with f_col3:
            search_query = st.text_input("Search IP, Username, or Raw String", placeholder="e.g. 203.0.113.5", key="tab1_search")

        filtered_logs = df_all_logs.copy()
        if event_filter != "All Events":
            filtered_logs = filtered_logs[filtered_logs["event_type"] == event_filter]
        if user_filter != "All Users":
            filtered_logs = filtered_logs[filtered_logs["username"] == user_filter]
        if search_query.strip():
            q = search_query.strip().lower()
            filtered_logs = filtered_logs[
                filtered_logs["source_ip"].str.lower().str.contains(q) |
                filtered_logs["username"].str.lower().str.contains(q) |
                filtered_logs["raw_entry"].str.lower().str.contains(q)
            ]

        st.caption(f"Showing {len(filtered_logs):,} of {len(df_all_logs):,} log entries.")

        # Clean compact display with truncated hash in monospace
        display_df = filtered_logs[["id", "timestamp", "username", "source_ip", "event_type", "entry_hash"]].copy()
        display_df["entry_hash"] = display_df["entry_hash"].apply(lambda h: f"{h[:10]}...{h[-6:]}" if len(str(h)) >= 16 else str(h))
        display_df = display_df.rename(columns={
            "id": "ID",
            "timestamp": "Timestamp",
            "username": "Username",
            "source_ip": "Source IP",
            "event_type": "Event Type",
            "entry_hash": "SHA-256 Hash",
        })
        st.dataframe(display_df, use_container_width=True, height=340)


# ===========================================================================
# TAB 2 — Attack Simulation
# ===========================================================================

with tab2:
    st.markdown('<div class="soc-section-heading">Attack Simulation & Threat Emulation</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Generate controlled authentication traffic to test the detection engine and cryptographic chaining.</div>', unsafe_allow_html=True)

    # 1-Click Attack Presets Section (Framed with distinct action buttons)
    with st.container(border=True):
        st.markdown("**Attack Scenario Presets**")
        st.caption("Execute instant multi-event threat vectors to evaluate detection rules and cryptographic alerts:")

        p_col1, p_col2, p_col3, p_col4, p_col5 = st.columns(5)

        with p_col1:
            if st.button("Brute Force Burst", icon=":material/bolt:", help="Generates 6 failed logins for 'alice' within 5 seconds", use_container_width=True):
                burst_now = datetime.now()
                for i in range(6):
                    t_str = (burst_now + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S")
                    lid = hash_chain.add_log_entry(t_str, "alice", "192.168.1.100", "login_failed")
                    all_logs = database.get_all_logs()
                    user_w = all_logs[all_logs["username"] == "alice"].tail(30)
                    c_row = {"timestamp": t_str, "username": "alice", "source_ip": "192.168.1.100", "event_type": "login_failed"}
                    hits = detection_engine.check_rules(c_row, user_w)
                    sev = detection_engine.classify_severity(hits, 0.0)
                    if sev != "None":
                        for reason in hits:
                            database.insert_alert(lid, reason, sev)
                st.error("Brute force burst generated: 6 failed attempts recorded for user 'alice'.")
                st.rerun()

        with p_col2:
            if st.button("Blacklisted IP", icon=":material/block:", help="Executes login from known malicious IP 203.0.113.5", use_container_width=True):
                t_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                lid = hash_chain.add_log_entry(t_str, "admin", "203.0.113.5", "login_failed")
                c_row = {"timestamp": t_str, "username": "admin", "source_ip": "203.0.113.5", "event_type": "login_failed"}
                hits = detection_engine.check_rules(c_row, pd.DataFrame())
                sev = detection_engine.classify_severity(hits, 0.0)
                for r in hits:
                    database.insert_alert(lid, r, sev)
                st.warning("Suspicious authentication simulated from blacklisted IP 203.0.113.5.")
                st.rerun()

        with p_col3:
            if st.button("Off-Hours Access", icon=":material/schedule:", help="Executes login simulated at 03:22 AM", use_container_width=True):
                t_str = datetime.now().strftime("%Y-%m-%d") + " 03:22:15"
                lid = hash_chain.add_log_entry(t_str, "finance_clerk", "10.0.0.15", "login_success")
                c_row = {"timestamp": t_str, "username": "finance_clerk", "source_ip": "10.0.0.15", "event_type": "login_success"}
                hits = detection_engine.check_rules(c_row, pd.DataFrame())
                sev = detection_engine.classify_severity(hits, 0.0)
                for r in hits:
                    database.insert_alert(lid, r, sev)
                st.warning("Off-hours authentication simulated at 03:22:15.")
                st.rerun()

        with p_col4:
            if st.button("High-Entropy User", icon=":material/fingerprint:", help="Simulates credential stuffing bot with high-entropy account name", use_container_width=True):
                t_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                bot_user = f"u_x8f!q9Z_{int(time.time())%1000}"
                lid = hash_chain.add_log_entry(t_str, bot_user, "198.51.100.99", "login_failed")
                c_row = {"timestamp": t_str, "username": bot_user, "source_ip": "198.51.100.99", "event_type": "login_failed"}
                ent = detection_engine.shannon_entropy(bot_user)
                hits = detection_engine.check_rules(c_row, pd.DataFrame())
                database.insert_alert(lid, f"high_entropy_username ({round(ent, 2)} bits)", "Medium")
                st.warning(f"High-entropy username generated: {bot_user} ({round(ent, 2)} bits).")
                st.rerun()

        with p_col5:
            if st.button("Legitimate User", icon=":material/verified_user:", help="Simulates routine employee login during business hours", use_container_width=True):
                t_str = datetime.now().strftime("%Y-%m-%d") + " 10:15:00"
                lid = hash_chain.add_log_entry(t_str, "bob", "192.168.1.15", "login_success")
                st.success(f"Legitimate login recorded for user 'bob' (Log ID {lid}).")
                st.rerun()

    st.markdown("---")

    # Custom Authentication Simulator: Tidy 2x2 Grid with equal heights
    st.markdown('<div class="soc-section-heading">Custom Authentication Simulator</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Submit custom credentials to evaluate anomaly classifications in real-time.</div>', unsafe_allow_html=True)

    with st.form("custom_login_sim_form", clear_on_submit=False):
        # Row 1: Username / Outcome
        c1_1, c1_2 = st.columns(2)
        with c1_1:
            m_user = st.text_input("Username", value="alice", help="Target username account")
        with c1_2:
            m_result = st.selectbox("Authentication Outcome", ["Success (login_success)", "Failed (login_failed)"])

        # Row 2: Password / Source IP Address
        c2_1, c2_2 = st.columns(2)
        with c2_1:
            m_pwd = st.text_input("Password", type="password", placeholder="(Simulated)")
        with c2_2:
            m_ip = st.text_input("Source IP Address", value="192.168.1.50")

        adv_exp = st.expander("Timestamp Override (Testing & Forensics)", expanded=False)
        with adv_exp:
            use_custom_time = st.checkbox("Override timestamp to test off-hours detection", value=False)
            custom_time_val = st.text_input("Custom Timestamp (YYYY-MM-DD HH:MM:SS)", value=datetime.now().strftime("%Y-%m-%d 02:30:00"))

        sim_submit = st.form_submit_button("Simulate Authentication Event", use_container_width=True, type="primary", icon=":material/play_arrow:")

    if sim_submit:
        if not m_user.strip():
            st.error("Username cannot be empty.")
        else:
            sim_ts = custom_time_val.strip() if use_custom_time else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ev_type = "login_success" if "Success" in m_result else "login_failed"

            new_log_id = hash_chain.add_log_entry(
                timestamp=sim_ts,
                username=m_user.strip(),
                source_ip=m_ip.strip() or "127.0.0.1",
                event_type=ev_type,
            )

            all_logs_df = database.get_all_logs()
            user_logs = all_logs_df[all_logs_df["username"] == m_user.strip()].tail(30)
            curr_row = {
                "timestamp": sim_ts,
                "username": m_user.strip(),
                "source_ip": m_ip.strip() or "127.0.0.1",
                "event_type": ev_type,
            }

            rule_hits = detection_engine.check_rules(curr_row, user_logs)
            recent_counts = pd.Series([1.0] * len(user_logs))
            z_score = detection_engine.compute_zscore(recent_counts, 1.0)
            entropy_val = detection_engine.shannon_entropy(m_user.strip())
            severity = detection_engine.classify_severity(rule_hits, z_score)

            if severity != "None":
                for r in rule_hits:
                    database.insert_alert(log_id=new_log_id, reason=r, severity=severity)
                if not rule_hits and abs(z_score) > 2:
                    database.insert_alert(log_id=new_log_id, reason="z_score_anomaly", severity=severity)

            # Clean verdict display
            if severity == "High":
                v_title = "Anomalous Authentication Detected (High Risk)"
                v_tag_class = "tag-critical"
            elif severity == "Medium":
                v_title = "Suspicious Authentication Detected (Medium Risk)"
                v_tag_class = "tag-elevated"
            elif severity == "Low":
                v_title = "Low Risk Behavior"
                v_tag_class = "tag-nominal"
            else:
                v_title = "Legitimate Access Recorded"
                v_tag_class = "tag-nominal"

            rules_str = ', '.join(rule_hits) if rule_hits else 'None'

            st.markdown(f"""
            <div class="verdict-box">
              <div class="verdict-header">
                <span class="verdict-title">{v_title}</span>
                <span class="threat-tag {v_tag_class}">SEVERITY: {severity}</span>
              </div>
              <div style="font-size: 0.82rem; color: #cbd5e1; margin-top: 0.4rem;">
                <strong>Triggered Rules:</strong> {rules_str} &nbsp;|&nbsp;
                <strong>Z-Score:</strong> {round(z_score, 2)} &nbsp;|&nbsp;
                <strong>Entropy:</strong> {round(entropy_val, 2)} bits
              </div>
              <div style="font-size: 0.76rem; color: #64748b; margin-top: 0.35rem;" class="mono">
                Log ID: {new_log_id} &nbsp;|&nbsp; Timestamp: {sim_ts} &nbsp;|&nbsp; Source IP: {m_ip}
              </div>
            </div>
            """, unsafe_allow_html=True)

    # Live Audit Stream: Last 10 Entries
    st.markdown('<div class="soc-section-heading">Recent Authentication Events</div>', unsafe_allow_html=True)
    all_logs_live = database.get_all_logs()
    if all_logs_live.empty:
        st.info("No recent authentication events recorded.")
    else:
        recent_10 = all_logs_live.tail(10).iloc[::-1][["id", "timestamp", "username", "source_ip", "event_type"]]
        recent_10 = recent_10.rename(columns={
            "id": "ID",
            "timestamp": "Timestamp",
            "username": "Username",
            "source_ip": "Source IP",
            "event_type": "Event Type",
        })
        st.dataframe(recent_10, use_container_width=True)


# ===========================================================================
# TAB 3 — Alerts
# ===========================================================================

with tab3:
    st.markdown('<div class="soc-section-heading">Security Alerts & Incident Queue</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Active threat indicators surfaced by deterministic rules, statistical outliers, and integrity audits.</div>', unsafe_allow_html=True)

    df_alerts = database.get_all_alerts()
    df_logs = database.get_all_logs()

    # KPI Summary Metric Cards at Top of Alerts Tab
    total_ev = len(df_logs)
    total_al = len(df_alerts)
    a_high = int((df_alerts["severity"] == "High").sum()) if not df_alerts.empty else 0
    a_med = int((df_alerts["severity"] == "Medium").sum()) if not df_alerts.empty else 0

    st.markdown(f"""
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Events</div>
        <div class="kpi-value">{total_ev:,}</div>
        <div class="kpi-subtext">Ingested ledger rows</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Alerts Raised</div>
        <div class="kpi-value">{total_al:,}</div>
        <div class="kpi-subtext">Active threat records</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">High Severity (Critical)</div>
        <div class="kpi-value" style="color:#ef4444">{a_high}</div>
        <div class="kpi-subtext">Immediate action required</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Medium Severity (Suspicious)</div>
        <div class="kpi-value" style="color:#f59e0b">{a_med}</div>
        <div class="kpi-subtext">Under investigation</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    if df_alerts.empty:
        st.info("No active security alerts recorded. Ingest logs or execute attack simulations to generate events.")
    else:
        # Join alerts with logs to provide source_ip and clean context
        alerts_merged = df_alerts.merge(
            df_logs[["id", "timestamp", "source_ip", "username"]],
            left_on="log_id",
            right_on="id",
            how="left",
            suffixes=("", "_log"),
        )

        rule_descriptions = {
            "failed_login_burst": "Exceeded failure threshold within 60-second window",
            "blacklisted_ip": "Source IP identified on external threat intelligence blacklist",
            "off_hours": "Authentication attempt recorded outside authorized operational hours (21:00-09:00)",
            "z_score_anomaly": "Statistical login frequency deviation exceeded threshold (|Z| > 2)",
            "tampering": "Cryptographic signature mismatch; entry modified after ledger write",
        }

        def _get_rule_desc(r):
            for key, desc in rule_descriptions.items():
                if key in str(r):
                    return desc
            return "Anomalous authentication pattern identified"

        alerts_merged["description"] = alerts_merged["reason"].apply(_get_rule_desc)

        # Multi-factor Filters
        af_col1, af_col2, af_col3 = st.columns([2, 2, 3])
        with af_col1:
            filter_sev = st.selectbox("Filter Severity", ["All Severities", "High", "Medium", "Low"], key="alert_tab_sev")
        with af_col2:
            all_reasons = ["All Trigger Reasons"] + sorted(df_alerts["reason"].unique().tolist())
            filter_reason = st.selectbox("Filter Reason", all_reasons, key="alert_tab_reason")
        with af_col3:
            alert_search = st.text_input("Search Alert Details", placeholder="Search by IP, reason, or log ID...", key="alert_tab_search")

        f_alerts = alerts_merged.copy()
        if filter_sev != "All Severities":
            f_alerts = f_alerts[f_alerts["severity"] == filter_sev]
        if filter_reason != "All Trigger Reasons":
            f_alerts = f_alerts[f_alerts["reason"] == filter_reason]
        if alert_search.strip():
            q = alert_search.strip().lower()
            f_alerts = f_alerts[
                f_alerts["reason"].str.lower().str.contains(q) |
                f_alerts["source_ip"].astype(str).str.lower().str.contains(q) |
                f_alerts["log_id"].astype(str).str.contains(q)
            ]

        st.caption(f"Displaying {len(f_alerts):,} alert record(s).")

        # Clean table with severity column (colored text tag only), timestamp, source IP, rule triggered, description
        display_alerts = f_alerts[["severity", "timestamp", "source_ip", "reason", "description", "log_id"]].copy()
        display_alerts = display_alerts.rename(columns={
            "severity": "Severity",
            "timestamp": "Timestamp",
            "source_ip": "Source IP",
            "reason": "Rule Triggered",
            "description": "Description",
            "log_id": "Log ID",
        })

        # Styling: colored text tag ONLY for severity column
        def _color_severity_text(val):
            if val == "High":
                return "color: #ef4444; font-weight: 600;"
            elif val == "Medium":
                return "color: #f59e0b; font-weight: 600;"
            elif val == "Low":
                return "color: #10b981; font-weight: 600;"
            return ""

        styled_alerts = _apply_style_map(display_alerts.style, _color_severity_text, subset=["Severity"])
        st.dataframe(styled_alerts, use_container_width=True, height=340)

        # Incident Mitigation Playbook Section
        st.markdown('<div class="soc-section-heading">Incident Response & Remediation Guidance</div>', unsafe_allow_html=True)
        st.markdown('<div class="soc-section-desc">Automated threat remediation playbooks based on active indicators.</div>', unsafe_allow_html=True)

        pb_col1, pb_col2 = st.columns(2)
        with pb_col1:
            st.markdown("""
            **Standard Operating Procedures:**
            - **`failed_login_burst`**: Apply exponential backoff delay and enforce multi-factor authentication.
            - **`blacklisted_ip`**: Ingest IP into edge firewall drop tables and inspect upstream proxy logs.
            - **`off_hours`**: Dispatch automated out-of-band verification challenge to account owner.
            - **`tampering`**: Isolate database host immediately; conduct memory and journal forensics.
            """)
        with pb_col2:
            st.markdown("**Incident Export**")
            csv_buf = io.StringIO()
            display_alerts.to_csv(csv_buf, index=False)
            st.download_button(
                label="Export Alerts Report (CSV)",
                data=csv_buf.getvalue(),
                file_name=f"soc_alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )


# ===========================================================================
# TAB 4 — Integrity Verification
# ===========================================================================

with tab4:
    st.markdown('<div class="soc-section-heading">Cryptographic Ledger Integrity</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Blockchain-style SHA-256 hash chaining: H(n) = SHA-256(Raw_Entry_n || H(n-1)). Any post-write alteration breaks chain continuity.</div>', unsafe_allow_html=True)

    chain_results = hash_chain.verify_chain()
    total_chain_len = len(chain_results)
    tampered_entries = [r for r in chain_results if r["status"] == "TAMPERED"]
    tampered_count = len(tampered_entries)
    verified_count = total_chain_len - tampered_count

    chain_status_text = "COMPROMISED" if tampered_count > 0 else ("VALID" if total_chain_len > 0 else "EMPTY")
    chain_status_color = "#ef4444" if tampered_count > 0 else ("#10b981" if total_chain_len > 0 else "#64748b")

    # KPI Summary Metric Cards at Top of Integrity Tab
    st.markdown(f"""
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Blocks</div>
        <div class="kpi-value">{total_chain_len:,}</div>
        <div class="kpi-subtext">Chained log records</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Blocks Verified</div>
        <div class="kpi-value">{verified_count:,}</div>
        <div class="kpi-subtext">Signature confirmed</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Tampered Blocks</div>
        <div class="kpi-value" style="color:{'#ef4444' if tampered_count > 0 else '#f8fafc'}">{tampered_count}</div>
        <div class="kpi-subtext">Mismatched hashes</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Chain Status</div>
        <div class="kpi-value" style="color:{chain_status_color}">{chain_status_text}</div>
        <div class="kpi-subtext">Cryptographic state</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Flat, Subtle Hash Chain Architecture Diagram
    st.markdown("""
    <div class="chain-diagram-container">
      <div class="chain-diagram-row">
        <div class="chain-block-node">
          <div class="chain-node-title">Genesis Anchor</div>
          <div class="chain-node-formula">Previous Hash: [0x0 / Root]</div>
        </div>
        <div class="chain-arrow">&rarr;</div>
        <div class="chain-block-node">
          <div class="chain-node-title">Block #{n-1}</div>
          <div class="chain-node-formula">H(n-1) = SHA-256(Raw_{n-1} || H_{n-2})</div>
        </div>
        <div class="chain-arrow">&rarr;</div>
        <div class="chain-block-node" style="border-color: #2563eb;">
          <div class="chain-node-title" style="color: #2563eb;">Current Block #{n}</div>
          <div class="chain-node-formula">H(n) = SHA-256(Raw_n || H_{n-1})</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Chain Audit Action Buttons
    audit_col1, audit_col2 = st.columns([3, 1])
    with audit_col1:
        run_verify = st.button("Run Chain Audit", use_container_width=True, type="primary")
    with audit_col2:
        if st.button("Resync / Repair Chain", help="Recalculate hashes sequentially from current database records", use_container_width=True):
            count_repaired = hash_chain.repair_chain()
            st.toast(f"Cryptographic chain repaired: {count_repaired} blocks updated.")
            st.rerun()

    if not chain_results:
        st.info("No log entries present in database. Add logs via Ingestion or Attack Simulation to verify ledger integrity.")
    else:
        # Concise Summary Display
        if not tampered_entries:
            st.markdown(f"""
            <div class="audit-summary-box audit-valid">
              <span class="threat-tag tag-nominal">VERIFIED</span>
              <span>All {total_chain_len:,} blocks verified successfully. Cryptographic chain integrity is intact.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            first_corrupted_id = tampered_entries[0]["log_id"]
            st.markdown(f"""
            <div class="audit-summary-box audit-tampered">
              <span class="threat-tag tag-critical">INTEGRITY FAILURE</span>
              <span>{len(tampered_entries)} of {total_chain_len:,} blocks failed verification, first at block #{first_corrupted_id}.</span>
            </div>
            """, unsafe_allow_html=True)

        # Audit Table with Truncated Hashes and Full-Row Tinting for Tampered Blocks
        audit_rows = []
        for r in chain_results:
            s_hash = str(r["stored_hash"])
            r_hash = str(r["recomputed_hash"])
            s_trunc = f"{s_hash[:10]}...{s_hash[-6:]}" if len(s_hash) >= 16 else s_hash
            r_trunc = f"{r_hash[:10]}...{r_hash[-6:]}" if len(r_hash) >= 16 else r_hash
            audit_rows.append({
                "Block ID": r["log_id"],
                "Stored Hash": s_trunc,
                "Recomputed Hash": r_trunc,
                "Status": r["status"],
                "Full Stored Hash": s_hash,
                "Full Recomputed Hash": r_hash,
            })

        audit_df = pd.DataFrame(audit_rows)
        display_audit_df = audit_df[["Block ID", "Stored Hash", "Recomputed Hash", "Status"]].copy()

        def _tint_tampered_rows(row):
            if row["Status"] == "TAMPERED":
                return ["background-color: rgba(239, 68, 68, 0.12); color: #fca5a5;"] * len(row)
            return [""] * len(row)

        styled_audit = display_audit_df.style.apply(_tint_tampered_rows, axis=1)
        st.dataframe(styled_audit, use_container_width=True, height=320)

        # Expander for Full Unabridged Hashes
        with st.expander("Full Cryptographic Hash Records (Unabridged)"):
            st.dataframe(
                audit_df[["Block ID", "Full Stored Hash", "Full Recomputed Hash", "Status"]],
                use_container_width=True,
                height=280,
            )

    st.markdown("---")

    # Tampering Demonstration Laboratory
    st.markdown('<div class="soc-section-heading">Tampering Demonstration Lab</div>', unsafe_allow_html=True)
    st.markdown('<div class="soc-section-desc">Simulate an attacker directly editing a database record in SQLite without updating the cryptographic digest.</div>', unsafe_allow_html=True)

    df_logs_for_tamper = database.get_all_logs()

    if df_logs_for_tamper.empty:
        st.info("Add log records to the database to evaluate the tampering demonstration.")
    else:
        t_col1, t_col2 = st.columns([1, 2])
        with t_col1:
            target_id = st.selectbox(
                "Select Log ID to Corrupt",
                options=df_logs_for_tamper["id"].tolist(),
                format_func=lambda x: f"Block #{x}",
                key="tamper_block_select",
            )
        with t_col2:
            fake_payload = st.text_input(
                "Injected Fake Payload (raw_entry)",
                value=f"TAMPERED_PAYLOAD|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|compromised_account|login_success",
                key="tamper_fake_input",
            )

        if st.button("Inject Database Tamper Payload", use_container_width=True):
            database.update_raw_entry(log_id=target_id, new_raw_entry=fake_payload)
            database.insert_alert(log_id=target_id, reason="tampering", severity="High")
            st.error(f"Block #{target_id} payload altered in SQLite without updating cryptographic digest.")
            st.rerun()
