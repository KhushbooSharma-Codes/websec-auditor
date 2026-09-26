# WebSec Auditor

A lightweight, automated Python CLI tool designed to inspect web server defensive configurations, audit critical HTTP security response headers, and validate SSL/TLS certificate integrity.

## Features

- **OWASP Header Audit:** Checks for missing security headers including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.
- **SSL/TLS Validation:** Connects directly via port 443 sockets to inspect peer certificates and calculate expiration windows.
- **Fingerprint Detection:** Detects information disclosure headers (e.g., exposed `Server` tokens, technology versions).
- **Risk Scoring & Export:** Automatically computes an overall grade (A to F) and outputs a detailed `scan_result.json` log.

## Installation & Setup

Clone the repository and install required packages:

bash
git clone [https://github.com/skhush4641-lab/websec-auditor.git](https://github.com/skhush4641-lab/websec-auditor.git)
cd websec-auditor
pip install requests urllib3


Usage
Run the auditor against any domain:

python websec_auditor.py


Output Preview

==================================================
 Audit Summary for [https://example.com](https://example.com)
 Overall Grade : C (64/100)
==================================================
[*] SSL Status   : Valid (63 days remaining)

[+] Enabled Headers:
    - X-Content-Type-Options
    - Referrer-Policy

[-] Missing Security Headers:
    - Strict-Transport-Security (Medium Risk)
    - Content-Security-Policy (High Risk)
    - X-Frame-Options (Medium Risk)

[!] Information Disclosure Warnings:
    - Server: cloudflare
==================================================
