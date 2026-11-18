# Mini-SIEM Log Triage Pipeline

A lightweight Security Information and Event Management (SIEM) tool built in Python. This tool ingests Linux `auth.log` files, parses failed and successful SSH login events, and applies correlation logic to detect brute-force attacks.

## Features
- **Parsing:** Extracts timestamps, usernames, IP addresses, and event types from raw syslog text using Regex.
- **Correlation:** Uses a sliding-window algorithm to detect multiple failed logins from a single IP within a specific timeframe.
- **Severity Triage:** Differentiates between standard brute-force attempts (WARNING) and successful breaches (CRITICAL) by correlating failed events with subsequent successful logins.

## How to Run
1. Clone the repo.
2. Run `python -m src.main`

## Sample Output
[*] Parsed 15 total events from data/auth.log
[*] Generated 2 alerts.

⚠️  WARNING: Failed Brute-force attempt from 192.168.1.50
    -> 5 failed logins starting at 2026-03-10 14:22:01
----------------------------------------
🚨 CRITICAL ALERT: SUCCESSFUL Brute-force from 203.0.113.42
    -> 4 failed logins, followed by a successful login!
----------------------------------------
<img width="1477" height="360" alt="image" src="https://github.com/user-attachments/assets/561a1242-b01d-4971-94a3-4bc5a6c89c46" />


## Lessons Learned & Limitations
- **Year parsing:** Syslog timestamps don't include the year, so I had to build logic to infer it.
- **Tuning:** A threshold of 5 catches slow brute forces but misses short ones. A threshold of 4 catches more but could increase false positives.
- **Next Steps:** In the future, I would like to add support for Windows Event Logs and output the alerts to a JSON file.
