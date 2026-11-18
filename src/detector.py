from datetime import timedelta
from collections import defaultdict

def detect_bruteforce(events, threshold=5, window_minutes=5):
    alerts = []
    
    # Group ALL events by IP address
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    # Define our sliding window
    window = timedelta(minutes=window_minutes)

    # Check each IP
    for ip, ip_events in by_ip.items():
        # Separate the failed and successful events for this specific IP
        failed_times = sorted([e["timestamp"] for e in ip_events if e["event_type"] == "failed"])
        success_times = sorted([e["timestamp"] for e in ip_events if e["event_type"] == "success"])
        
        # Sliding window logic (ONLY looking at failed_times)
        for i, start_time in enumerate(failed_times):
            # Count how many FAILED events happened in the window
            count = sum(1 for t in failed_times[i:] if t - start_time <= window)
            
            if count >= threshold:
                # Did they succeed after they started failing?
                successful_after_attack = any(t >= start_time for t in success_times)
                
                alerts.append({
                    "ip": ip, 
                    "count": count, 
                    "window_start": start_time,
                    "attack_succeeded": successful_after_attack 
                })
                break  # One alert per IP is enough for now
                
    return alerts