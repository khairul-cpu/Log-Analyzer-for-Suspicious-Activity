# analyzer.py
import re
import sys
from collections import defaultdict

# Regex patterns
FAILED_LOGIN = re.compile(r"(401|403)")
SQLI_PATTERN = re.compile(r"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|--|;)", re.IGNORECASE)

def analyze_log(file_path):
    suspicious_ips = defaultdict(lambda: {"failed_logins": 0, "sqli_attempts": 0})

    try:
        with open(file_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 9:
                    continue
                ip = parts[0]
                status = parts[8]

                # Detect failed logins
                if FAILED_LOGIN.search(status):
                    suspicious_ips[ip]["failed_logins"] += 1

                # Detect SQLi patterns
                if SQLI_PATTERN.search(line):
                    suspicious_ips[ip]["sqli_attempts"] += 1

    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return

    print("\n=== Suspicious Activity Report ===")
    for ip, activity in suspicious_ips.items():
        if activity["failed_logins"] > 3 or activity["sqli_attempts"] > 0:
            print(f"\n[IP] {ip}")
            if activity["failed_logins"]:
                print(f"  - Failed Logins: {activity['failed_logins']}")
            if activity["sqli_attempts"]:
                print(f"  - SQLi Attempts: {activity['sqli_attempts']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <logfile>")
        sys.exit(1)

    log_file = sys.argv[1]
    analyze_log(log_file)
