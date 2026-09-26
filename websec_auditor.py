import sys
import json
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"risk": "Medium", "desc": "Forces HTTPS connections (HSTS)"},
    "Content-Security-Policy": {"risk": "High", "desc": "Mitigates XSS and malicious script execution"},
    "X-Frame-Options": {"risk": "Medium", "desc": "Prevents clickjacking framing"},
    "X-Content-Type-Options": {"risk": "Low", "desc": "Prevents MIME-type sniffing"},
    "Referrer-Policy": {"risk": "Low", "desc": "Controls referrer information leakage"}
}

FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def get_ssl_details(hostname):
    
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                days_left = (exp_date - datetime.now(timezone.utc)).days
                return {
                    "valid": days_left > 0,
                    "days_left": days_left,
                    "expires_on": cert['notAfter']
                }
    except Exception as err:
        return {"valid": False, "error": str(err)}


def scan_host(target_url):
    target_url = normalize_url(target_url)
    parsed = urlparse(target_url)
    host = parsed.hostname

    print(f"\n[+] Target: {target_url}")
    print("[+] Running audit...")

    score = 100
    results = {
        "url": target_url,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ssl": {},
        "missing_headers": [],
        "present_headers": [],
        "exposed_headers": [],
        "score": 0,
        "grade": ""
    }

    # SSL
    if parsed.scheme == "https":
        ssl_info = get_ssl_details(host)
        results["ssl"] = ssl_info
        if not ssl_info.get("valid"):
            score -= 30
    else:
        results["ssl"] = {"warning": "Target runs on plain HTTP"}
        score -= 40

    # Header analysis
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
        res = requests.get(target_url, headers=headers, timeout=10, verify=False)
        server_headers = res.headers
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None

    # check  headers
    for h, meta in SECURITY_HEADERS.items():
        if h in server_headers:
            results["present_headers"].append(h)
        else:
            results["missing_headers"].append({
                "header": h,
                "risk": meta["risk"],
                "description": meta["desc"]
            })
            score -= (15 if meta["risk"] == "High" else 8)

    for leak in FINGERPRINT_HEADERS:
        if leak in server_headers:
            results["exposed_headers"].append({
                "header": leak,
                "value": server_headers[leak]
            })
            score -= 5

    final_score = max(0, score)
    results["score"] = final_score

    if final_score >= 85:
        results["grade"] = "A"
    elif final_score >= 70:
        results["grade"] = "B"
    elif final_score >= 50:
        results["grade"] = "C"
    else:
        results["grade"] = "F"

    return results


def print_report(data):
    if not data:
        return

    print("\n" + "=" * 50)
    print(f" Audit Summary for {data['url']}")
    print(f" Overall Grade : {data['grade']} ({data['score']}/100)")
    print("=" * 50)

    ssl_data = data.get("ssl", {})
    if "days_left" in ssl_data:
        print(f"[*] SSL Status   : Valid ({ssl_data['days_left']} days remaining)")
    elif "warning" in ssl_data:
        print(f"[!] SSL Status   : {ssl_data['warning']}")
    elif "error" in ssl_data:
        print(f"[!] SSL Status   : Failed ({ssl_data['error']})")

    print("\n[+] Enabled Headers:")
    if data["present_headers"]:
        for h in data["present_headers"]:
            print(f"    - {h}")
    else:
        print("    None detected")

    print("\n[-] Missing Security Headers:")
    if data["missing_headers"]:
        for item in data["missing_headers"]:
            print(f"    - {item['header']} ({item['risk']} Risk)")
    else:
        print("    All standard headers present")

    if data["exposed_headers"]:
        print("\n[!] Information Disclosure Warnings:")
        for item in data["exposed_headers"]:
            print(f"    - {item['header']}: {item['value']}")

    print("=" * 50 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL: ").strip()

    if not target:
        print("[-] Target cannot be empty.")
        sys.exit(1)

    audit_data = scan_host(target)

    if audit_data:
        print_report(audit_data)

        out_file = "scan_result.json"
        with open(out_file, "w") as f:
            json.dump(audit_data, f, indent=2)
        print(f"[+] Full JSON report exported to {out_file}")
