# Security Log Analyzer & Anomaly Detector

A **Python + Streamlit** web application that ingests login-event CSV logs or captures live login simulations, then applies rule-based checks (failed-login bursts, blacklisted IPs, off-hours access) and statistical Z-score analysis to surface anomalies — all without any ML model training. Every log entry is chained together with a SHA-256 hash so that any post-write tampering is immediately detectable via the built-in integrity verifier. Alerts are stored in a local SQLite database and can be filtered by severity (High / Medium / Low) in a dedicated dashboard tab.

## How to run

```bash
# 1. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the app
streamlit run app.py
```

The browser will open automatically at http://localhost:8501. On first run, `logs.db` is created automatically — it is safe to delete it to reset all data.
