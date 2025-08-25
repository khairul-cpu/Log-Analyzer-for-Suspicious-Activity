# Log-Analyzer-for-Suspicious-Activity
a Python script that parses Apache/Nginx logs (or Windows Event Logs) and flags brute-force attempts, SQLi patterns, or unusual IPs.
A lightweight Python tool to analyze Apache/Nginx access logs for suspicious activity such as:

1) Multiple failed logins
2) SQL injection (SQLi) attempts
3) Other suspicious patterns (extensible)

This project is designed for defenders, SOC analysts, and students who want to quickly detect common attack behaviors in server logs.

Features:
1) Detects repeated failed login attempts (brute force indicator).
2) Identifies common SQL injection payloads in request URLs.
3) Simple CLI tool – run it on any log file.
4) Extensible with your own detection rules.
5) Open source & beginner-friendly.


you may download the sample log and test it later with the python script :)
