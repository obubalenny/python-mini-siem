import re
from datetime import datetime

# Match lines like:
# Mar 10 14:22:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44221 ssh2
FAILED_LOGIN_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESS_LOGIN_RE = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_line(line: str, year: int = 2026):
    # Check for Failed
    match = FAILED_LOGIN_RE.search(line)
    if match:
        ts = datetime.strptime(f"{year} {match['timestamp']}", "%Y %b %d %H:%M:%S")
        return {"timestamp": ts, "user": match["user"], "ip": match["ip"], "event_type": "failed"}

    # Check for Success
    match = SUCCESS_LOGIN_RE.search(line)
    if match:
        ts = datetime.strptime(f"{year} {match['timestamp']}", "%Y %b %d %H:%M:%S")
        return {"timestamp": ts, "user": match["user"], "ip": match["ip"], "event_type": "success"}

    return None

if __name__ == "__main__":
    test_line = "Mar 10 14:22:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44221 ssh2"
    print(parse_line(test_line))