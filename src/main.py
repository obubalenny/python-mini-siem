from src.parser import parse_line
from src.detector import detect_bruteforce

def main(log_path):
    events = []
    
    # 1. Ingest and Parse
    with open(log_path, "r") as f:
        for line in f:
            ev = parse_line(line.strip())
            if ev:
                events.append(ev)
                
    print(f"[*] Parsed {len(events)} total events from {log_path}")
    
    # 2. Correlate and Alert
    # Change threshold to 4 or 5 here to test!
    alerts = detect_bruteforce(events, threshold=4, window_minutes=5)
    
    print(f"[*] Generated {len(alerts)} alerts.\n")
    
    # 3. Output
    for alert in alerts:
        if alert["attack_succeeded"]:
            print(f"🚨 CRITICAL ALERT: SUCCESSFUL Brute-force from {alert['ip']}")
            print(f"    -> {alert['count']} failed logins, followed by a successful login!")
        else:
            print(f"⚠️  WARNING: Failed Brute-force attempt from {alert['ip']}")
            print(f"    -> {alert['count']} failed logins starting at {alert['window_start']}")
        print("-" * 40)

if __name__ == "__main__":
    main("data/auth.log")