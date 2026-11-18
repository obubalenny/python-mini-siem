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
*(Paste the exact terminal output you got with threshold=4 here)*

## Lessons Learned & Limitations
- **Year parsing:** Syslog timestamps don't include the year, so I had to build logic to infer it.
- **Tuning:** A threshold of 5 catches slow brute forces but misses short ones. A threshold of 4 catches more but could increase false positives.
- **Next Steps:** In the future, I would like to add support for Windows Event Logs and output the alerts to a JSON file.