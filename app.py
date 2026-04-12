from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# -------------------- ROUTES --------------------

@app.route('/')
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    try:
        body = request.get_json()

        if not body:
            return jsonify({"error": "Invalid JSON"}), 400

        url = body.get("url", "").strip()
        checks = body.get("checks", ["sql", "xss", "auth"])

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        all_findings = []
        start_time = time.time()

        if "sql" in checks:
            all_findings += check_sql_injection(url)
        if "xss" in checks:
            all_findings += check_xss(url)
        if "auth" in checks:
            all_findings += check_broken_auth(url)

        duration = round(time.time() - start_time, 2)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = {}

        for f in all_findings:
            sev = f.get("severity", "low")
            severity_counts[sev] += 1
            type_counts[f["type"]] = type_counts.get(f["type"], 0) + 1

        return jsonify({
            "meta": {
                "url": url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": duration,
            },
            "findings": all_findings,
            "summary": {
                "total": len(all_findings),
                "severity_counts": severity_counts,
                "type_counts": type_counts,
                "risk_score": calculate_risk_score(all_findings),
            }
        })

    except Exception as e:
        print("ERROR:", e)
        return jsonify({"error": str(e)}), 500


#  SQL injection 

SQL_PAYLOADS =[
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error.*sql",
    r"microsoft ole db provider for sql server",
    r"pg_query\(\)",
    r"sqlite_master",
    r"ora-\d{5}",
    r"postgresql.*error",
]
# ─── XSS Configuration ───────────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'><script>alert(1)</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
]

# ─── Broken Auth Configuration ───────────────────────────────────────────────
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
]

SENSITIVE_PATHS = [
    "/admin",
    "/admin/login",
    "/wp-admin",
    "/login",
    "/dashboard",
    "/api/users",
    "/config",
    "/.env",
    "/backup",
    "/phpmyadmin",
    "/server-status",
    "/console",
]


def extract_forms(url):
    forms = []
    try:
        res = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, 'html.parser')

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            inputs = []

            for field in form.find_all(["input", "textarea"]):
                name = field.get("name")
                if name:
                    inputs.append({
                        "type": field.get("type", "text"),
                        "name": name
                    })

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

    except Exception as e:
        print("Form extraction error:", e)

    return forms


def check_sql_injection(url):
    findings = []
    forms = extract_forms(url)

    for form in forms:
        target = urllib.parse.urljoin(url, form["action"])

        for payload in SQL_PAYLOADS:
            data = {f["name"]: payload for f in form["inputs"]}

            try:
                res = requests.post(target, data=data, timeout=10, verify=False)
                response_text = res.text.lower()
                if any(re.search(pattern, response_text) for pattern in SQL_ERROR_PATTERNS):
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "critical",
                        "location": target,
                        "payload": payload,
                        "detail": "SQL error pattern detected in response"
                    })
            except Exception as e:
                print("SQL check error:", e)

    return findings


def check_xss(url):
    findings = []
    forms = extract_forms(url)

    for form in forms:
        target = urllib.parse.urljoin(url, form["action"])

        for payload in XSS_PAYLOADS:
            data = {f["name"]: payload for f in form["inputs"]}

            try:
                res = requests.post(target, data=data, timeout=10, verify=False)
                if payload in res.text:
                    findings.append({
                        "type": "XSS",
                        "severity": "high",
                        "location": target,
                        "payload": payload,
                        "detail": "Payload reflected in response"
                    })
            except Exception as e:
                print("XSS check error:", e)

    return findings


def check_broken_auth(url):
    findings = []
    try:
        res = requests.get(url, timeout=10, verify=False)
        missing = [h for h in SECURITY_HEADERS if h not in res.headers]

        if missing:
            findings.append({
                "type": "Broken Auth",
                "severity": "medium",
                "location": url,
                "payload": "",
                "detail": f"Missing headers: {missing}"
            })
    except Exception as e:
        print("Auth check error:", e)

    return findings


def calculate_risk_score(findings):
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    return min(score, 100)


# -------------------- RUN --------------------

if __name__ == '__main__':
    app.run(debug=True, port=5000)