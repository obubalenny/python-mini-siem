import pytest
from datetime import datetime
from src.parser import parse_line

def test_parse_failed_login():
    line = "Mar 10 14:22:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 44221 ssh2"
    result = parse_line(line)
    
    assert result is not None
    assert result["ip"] == "192.168.1.50"
    assert result["user"] == "admin"
    assert result["event_type"] == "failed"
    assert result["timestamp"] == datetime(2026, 3, 10, 14, 22, 1)

def test_parse_success_login():
    line = "Mar 10 14:25:14 server sshd[1245]: Accepted password for alice from 203.0.113.42 port 38914 ssh2"
    result = parse_line(line)
    
    assert result is not None
    assert result["ip"] == "203.0.113.42"
    assert result["user"] == "alice"
    assert result["event_type"] == "success"

def test_parse_ignores_noise():
    line = "Mar 10 14:28:30 server sshd[1246]: Invalid user postgres from 198.51.100.88 port 60112"
    result = parse_line(line)
    
    # This line is not a failed or successful login, so it should return None
    assert result is None