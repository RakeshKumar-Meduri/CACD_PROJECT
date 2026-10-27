"""
generate_sample_data.py — scratch script to produce data/sample_dataset.csv.
Run once: python generate_sample_data.py
"""

import csv
import random
from datetime import datetime, timedelta

USERNAMES = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "hank"]
# IPs — 203.0.113.5 and 198.51.100.23 are in the BLACKLIST
IPS = [
    "192.168.1.10", "192.168.1.11", "10.0.0.5", "10.0.0.8",
    "172.16.0.3", "172.16.0.9", "203.0.113.5", "198.51.100.23",
    "192.168.2.50", "10.10.10.1",
]
BLACKLIST_IPS = {"203.0.113.5", "198.51.100.23"}

random.seed(42)

rows = []

# Base time: 2024-01-15 08:00:00 — we'll spread events across ~6 hours
base_time = datetime(2024, 1, 15, 8, 0, 0)

# ---- Normal traffic (09:00–21:00, mix of success/fail) --------------------
t = datetime(2024, 1, 15, 9, 0, 0)
for _ in range(80):
    t += timedelta(seconds=random.randint(30, 180))
    user = random.choice(USERNAMES[:6])     # normal users
    ip   = random.choice(IPS[:6])           # non-blacklisted IPs
    etype = "login_success" if random.random() > 0.2 else "login_failed"
    label = "normal"
    rows.append((t.strftime("%Y-%m-%d %H:%M:%S"), user, ip, etype, label))

# ---- Off-hours traffic (2 AM – 4 AM) — triggers off_hours rule -----------
t_night = datetime(2024, 1, 15, 2, 0, 0)
for _ in range(12):
    t_night += timedelta(seconds=random.randint(60, 300))
    user = random.choice(["eve", "frank"])
    ip   = random.choice(IPS[:4])
    etype = random.choice(["login_success", "login_failed"])
    label = "attack"
    rows.append((t_night.strftime("%Y-%m-%d %H:%M:%S"), user, ip, etype, label))

# ---- Brute-force burst cluster 1 (>5 failed logins in 60 s) -------------
t_burst1 = datetime(2024, 1, 15, 14, 30, 0)
for i in range(8):
    t_burst1 += timedelta(seconds=random.randint(3, 8))
    rows.append((t_burst1.strftime("%Y-%m-%d %H:%M:%S"),
                 "eve", "10.0.0.5", "login_failed", "attack"))

# ---- Brute-force burst cluster 2 (different user/IP) ---------------------
t_burst2 = datetime(2024, 1, 15, 16, 15, 0)
for i in range(7):
    t_burst2 += timedelta(seconds=random.randint(4, 9))
    rows.append((t_burst2.strftime("%Y-%m-%d %H:%M:%S"),
                 "dave", "172.16.0.3", "login_failed", "attack"))

# ---- Blacklisted IP events -----------------------------------------------
t_bl = datetime(2024, 1, 15, 11, 0, 0)
for _ in range(10):
    t_bl += timedelta(seconds=random.randint(60, 240))
    user = random.choice(USERNAMES)
    ip   = random.choice(["203.0.113.5", "198.51.100.23"])
    etype = random.choice(["login_success", "login_failed"])
    label = "attack"
    rows.append((t_bl.strftime("%Y-%m-%d %H:%M:%S"), user, ip, etype, label))

# ---- Mixed late-day normal traffic ----------------------------------------
t_late = datetime(2024, 1, 15, 18, 0, 0)
for _ in range(33):
    t_late += timedelta(seconds=random.randint(20, 120))
    user  = random.choice(USERNAMES[:5])
    ip    = random.choice(IPS[:6])
    etype = "login_success" if random.random() > 0.15 else "login_failed"
    label = "normal"
    rows.append((t_late.strftime("%Y-%m-%d %H:%M:%S"), user, ip, etype, label))

# Sort by timestamp so the CSV is in chronological order
rows.sort(key=lambda r: r[0])

output_path = "data/sample_dataset.csv"
with open(output_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "username", "source_ip", "event_type", "label"])
    writer.writerows(rows)

print(f"Generated {len(rows)} rows -> {output_path}")
