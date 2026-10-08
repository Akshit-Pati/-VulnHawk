"""
=========================================================
 VulnHawk Configuration File
 Author : Sanjana Reddy
 Project : VulnHawk
=========================================================
"""

import os

# =========================================================
# Project Information
# =========================================================

PROJECT_NAME = "VulnHawk"
VERSION = "1.0.0"

AUTHOR = "Sanjana Reddy"

# =========================================================
# Network Configuration
# =========================================================

REQUEST_TIMEOUT = 10

MAX_REDIRECTS = 5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0 Safari/537.36 VulnHawk/1.0"
)

VERIFY_SSL = True

# =========================================================
# Scan Configuration
# =========================================================

MAX_THREADS = 10

CRAWL_DEPTH = 2

FOLLOW_REDIRECTS = True

# =========================================================
# Report Configuration
# =========================================================

REPORT_FOLDER = "reports"

HTML_REPORT = os.path.join(REPORT_FOLDER, "report.html")

JSON_REPORT = os.path.join(REPORT_FOLDER, "report.json")

PDF_REPORT = os.path.join(REPORT_FOLDER, "report.pdf")

# =========================================================
# Payload Files
# =========================================================

PAYLOAD_FOLDER = "payloads"

SQLI_PAYLOADS = os.path.join(PAYLOAD_FOLDER, "sqli.txt")

XSS_PAYLOADS = os.path.join(PAYLOAD_FOLDER, "xss.txt")

DIRECTORY_WORDLIST = os.path.join(PAYLOAD_FOLDER, "directories.txt")

# =========================================================
# Severity Levels
# =========================================================

SEVERITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
}

# =========================================================
# Security Headers
# =========================================================

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# =========================================================
# Common Web Ports
# =========================================================

COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    3306,
    3389,
    8080,
    8443
]