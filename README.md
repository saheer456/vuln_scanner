# VulnScan — Web Application Vulnerability Scanner

A final year project built with **Flask** and **vanilla JavaScript** that scans web applications for common security vulnerabilities and presents results in an interactive dashboard.

---

## Features

- **SQL Injection Detection** — Submits SQL payloads into discovered forms and checks responses against known database error patterns
- **XSS Detection** — Tests for reflected Cross-Site Scripting by injecting HTML/JS payloads into form fields
- **Broken Auth / Missing Security Headers** — Checks for the absence of critical HTTP security headers
- **Risk Score** — Calculates a weighted risk score (0–100) based on finding severity
- **Interactive Dashboard** — Live progress bar, animated counters, Chart.js doughnut and bar charts
- **Severity Filtering** — Filter findings by Critical, High, Medium in the results table

---

## Tech Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Backend  | Python 3, Flask 3.0                 |
| Scraping | Requests, BeautifulSoup4            |
| Frontend | HTML5, Vanilla CSS, Vanilla JS      |
| Charts   | Chart.js (CDN)                      |
| Fonts    | Google Fonts (Rajdhani, Share Tech Mono) |

---

## Project Structure

```
vuln_Scanner/
├── app.py                  # Flask backend — scan engine
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Main UI template
└── static/
    ├── css/style.css       # Dark cyber-themed stylesheet
    └── js/script.js        # Frontend scan orchestration + charts
```

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/vuln_scanner.git
cd vuln_scanner
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

The app will start at **http://localhost:5000**

---

## Usage

1. Open `http://localhost:5000` in your browser
2. Enter the target URL in the input field
3. Select the vulnerability checks to run (SQL Injection, XSS, Broken Auth)
4. Click **▶ SCAN**
5. View the results dashboard — severity breakdown charts, risk score, and detailed findings

---

## Vulnerability Checks Explained

### SQL Injection
Extracts all forms from the target page, injects SQL payloads into each input field, and checks the response for known database error patterns (MySQL, PostgreSQL, SQLite, Oracle, MSSQL).

### XSS (Cross-Site Scripting)
Injects common HTML/JavaScript payloads and checks whether they are reflected back unescaped in the server response.

### Broken Auth / Security Headers
Performs a GET request and checks for the presence of these critical HTTP response headers:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-XSS-Protection`
- `Referrer-Policy`

---

## Risk Score

| Severity | Weight |
|----------|--------|
| Critical | 40     |
| High     | 20     |
| Medium   | 10     |
| Low      | 5      |

Score is capped at **100**.

---

## Dependencies

```
flask==3.0.3
requests==2.32.3
beautifulsoup4==4.12.3
urllib3==2.2.1
```

---

## Disclaimer

> This tool is developed for **educational purposes** as part of a final year academic project.  
> **Only scan websites and systems you own or have explicit written permission to test.**  
> Unauthorized scanning is illegal and unethical.

---

## Author

Developed as a Final Year Project — 2026
