from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

import os
from dotenv import load_dotenv

load_dotenv()
import threading
import uuid
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from scanner.crawler import WebCrawler
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from utils.target_validator import validate_target_url

from scanner.header_scanner import HeaderScanner
from scanner.http_discovery import HTTPDiscovery
from scanner.ssl_checker import SSLChecker
from scanner.technologies import TechnologyDetector
from scanner.path_traversal import PathTraversalScanner
from scanner.robots_checker import RobotsChecker
from scanner.sitemap_checker import SitemapChecker
from scanner.cookies import CookieScanner
from scanner.port_scanner import PortScanner
from scanner.security_score import SecurityScore
from scanner.xss_scanner import XSSScanner
from scanner.sqli_scanner import SQLiScanner
from scanner.open_redirect import OpenRedirectScanner


limiter = Limiter(key_func=get_remote_address)

# =========================================================
# API Authentication
# =========================================================

security_scheme = HTTPBearer()

API_KEY = os.getenv("VULNHAWK_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "VULNHAWK_API_KEY environment variable is required."
    )


def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
):
    if credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key."
        )

    return True
# =========================================================
# VulnHawk API
# =========================================================

app = FastAPI(
    title="VulnHawk API",
    description="Automated Web Application Vulnerability Scanner API",
    version="1.1.0"
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# Request Models
# =========================================================

class ScanRequest(BaseModel):
    target: HttpUrl


# =========================================================
# In-memory scan jobs
# =========================================================

scan_jobs: Dict[str, Dict[str, Any]] = {}

# Maximum number of scans allowed to run simultaneously
MAX_ACTIVE_SCANS = 3

# Thread-safe counter for active scans
active_scan_count = 0
active_scan_lock = threading.Lock()


# =========================================================
# Root
# =========================================================

@app.get("/")
def root():
    return {
        "project": "VulnHawk",
        "status": "online",
        "message": "VulnHawk API is running"
    }


# =========================================================
# Health Check
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# =========================================================
# Internal progress helper
# =========================================================

def update_progress(
    job_id: str,
    stage: str,
    progress: int,
    status: str = "running"
):
    if job_id in scan_jobs:
        scan_jobs[job_id].update({
            "stage": stage,
            "progress": progress,
            "status": status
        })


# =========================================================
# Background scan worker
# =========================================================

def run_scan(job_id: str, target: str):
    try:
        results = {
            "target": target,
            "http_discovery": {},
            "crawl": {},
            "headers": {},
            "ssl": {},
            "technologies": {},
            "robots": {},
            "sitemap": {},
            "cookies": {},
            "ports": {},
            "xss": {},
            "sqli": {},
            "path_traversal": {},
            "open_redirect": {}
        }

        # -------------------------------------------------
        # HTTP / HTTPS Discovery
        # -------------------------------------------------
        update_progress(
            job_id,
            "HTTP / HTTPS Discovery",
            8
        )

        results["http_discovery"] = HTTPDiscovery.check(target)

        # -------------------------------------------------
        # Web Crawler
        # -------------------------------------------------
        update_progress(
            job_id,
            "Web Application Crawling",
            14
        )

        results["crawl"] = WebCrawler.crawl(
            target,
            max_pages=10,
            max_depth=2
        )

        # -------------------------------------------------
        # Security Headers
        # -------------------------------------------------
        update_progress(
            job_id,
            "Security Headers",
            18
        )

        results["headers"] = HeaderScanner.scan(target)                                 # -------------------------------------------------
        # Security Headers
        # -------------------------------------------------
        update_progress(job_id, "Security Headers", 18)
        results["headers"] = HeaderScanner.scan(target)

        # -------------------------------------------------
        # SSL / TLS
        # -------------------------------------------------
        update_progress(job_id, "SSL / TLS Analysis", 22)
        results["ssl"] = SSLChecker.scan(target)

        # -------------------------------------------------
        # Technology Detection
        # -------------------------------------------------
        update_progress(job_id, "Technology Detection", 34)
        results["technologies"] = TechnologyDetector.scan(target)

        # -------------------------------------------------
        # robots.txt
        # -------------------------------------------------
        update_progress(job_id, "robots.txt Analysis", 46)
        results["robots"] = RobotsChecker.scan(target)

        # -------------------------------------------------
        # sitemap.xml
        # -------------------------------------------------
        update_progress(job_id, "sitemap.xml Analysis", 58)
        results["sitemap"] = SitemapChecker.scan(target)

        # -------------------------------------------------
        # Cookies
        # -------------------------------------------------
        update_progress(job_id, "Cookie Security Analysis", 70)
        results["cookies"] = CookieScanner.scan(target)

        # -------------------------------------------------
        # Nmap Port Scan
        # -------------------------------------------------
        update_progress(job_id, "Nmap Port Scan", 84)
        results["ports"] = PortScanner.scan(target)

        # -------------------------------------------------
        # XSS Reflection Analysis
        # -------------------------------------------------
        update_progress(
            job_id,
            "XSS Reflection Analysis",
            90
        )

        parameter_map = results.get("crawl", {}).get(
            "parameter_map",
            {}
        )

        results["xss"] = XSSScanner.scan(
            target,
            parameter_map
        )
        # -------------------------------------------------
        # SQL Injection Analysis
        # -------------------------------------------------
        update_progress(
            job_id,
            "SQL Injection Analysis",
            92
        )

        results["sqli"] = SQLiScanner.scan(
            target,
            parameter_map
        )
        # -------------------------------------------------
        # Path Traversal Analysis
        # -------------------------------------------------
        update_progress(
            job_id,
            "Path Traversal Analysis",
            93
        )

        results["path_traversal"] = PathTraversalScanner.scan(
            target,
            parameter_map
        )
        
        # -------------------------------------------------
        # Open Redirect Analysis
        # -------------------------------------------------
        update_progress(
            job_id,
            "Open Redirect Analysis",
            94
        )

        results["open_redirect"] = OpenRedirectScanner.scan(
            target,
            parameter_map
        )

        # -------------------------------------------------
        # Security Score
        # -------------------------------------------------
        update_progress(job_id, "Calculating Security Score", 95)
        security = SecurityScore.calculate(results)


        # -------------------------------------------------
        # Merge Evidence-Based Active Testing Findings
        # -------------------------------------------------
        active_findings = []

        for scanner_key in [
            "xss",
            "sqli",
            "path_traversal",
            "open_redirect",
        ]:
            scanner_result = results.get(scanner_key, {})

            if isinstance(scanner_result, dict):
                scanner_findings = scanner_result.get("findings", [])

                if isinstance(scanner_findings, list):
                    active_findings.extend(scanner_findings)

        # Add active testing findings to the main security findings list
        security["findings"].extend(active_findings)
        # Remove duplicate findings while preserving stronger evidence
        security["findings"] = SecurityScore.deduplicate_findings(
            security["findings"],
            results.get("target", "Unknown")
        )

        # Keep finding count synchronized
        security["total_findings"] = len(security["findings"])

        
        # -------------------------------------------------
        # Completed
        # -------------------------------------------------
        scan_jobs[job_id].update({
            "status": "completed",
            "stage": "Scan Completed",
            "progress": 100,
            "result": {
                "status": "completed",
                "security": security,
                "results": results
            }
        })

    except Exception as e:
        scan_jobs[job_id].update({
            "status": "failed",
            "stage": "Scan Failed",
            "progress": 100,
            "error": str(e)
        })

    finally:
        global active_scan_count

        with active_scan_lock:
            active_scan_count = max(0, active_scan_count - 1)


# =========================================================
# Start Scan
# =========================================================

@app.post("/scan/start")
@limiter.limit("5/minute")
def start_scan(
    request: Request,
    scan_request: ScanRequest,
    authenticated: bool = Depends(verify_api_key)
):
    target = str(scan_request.target)

    is_valid, validation_message = validate_target_url(target)

    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=validation_message
        )


    global active_scan_count

    with active_scan_lock:
        if active_scan_count >= MAX_ACTIVE_SCANS:
            raise HTTPException(
                status_code=429,
                detail="Maximum number of concurrent scans reached. Please try again later."
            )

        active_scan_count += 1

    is_valid, validation_message = validate_target_url(target)

    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=validation_message
        )

    job_id = str(uuid.uuid4())

    scan_jobs[job_id] = {
        "job_id": job_id,
        "target": target,
        "status": "starting",
        "stage": "Initializing Scan",
        "progress": 0,
        "result": None,
        "error": None
    }

    thread = threading.Thread(
        target=run_scan,
        args=(job_id, target),
        daemon=True
    )
    thread.start()

    return {
        "job_id": job_id,
        "status": "started",
        "target": target
    }


# =========================================================
# Scan Progress / Status
# =========================================================

app.get("/scan/status/{job_id}")
def get_scan_status(
    job_id: str,
    authenticated: bool = Depends(verify_api_key)
):
    job = scan_jobs.get(job_id)

    if not job:
        raise HTTPException(
            status_code=404,
            detail="Scan job not found"
        )

    return job


# =========================================================
# Legacy synchronous Scan Endpoint
# =========================================================

@app.post("/scan")
def scan_target(
    request: ScanRequest,
    authenticated: bool = Depends(verify_api_key)
):
    """
    Keeps the original /scan endpoint available for compatibility.
    New frontend integrations should use /scan/start and
    /scan/status/{job_id} for real-time progress.
    """

    target = str(request.target)

    is_valid, validation_message = validate_target_url(target)

    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=validation_message
        )

    try:
        results = {
            "target": target,
            "headers": {},
            "ssl": {},
            "technologies": {},
            "robots": {},
            "sitemap": {},
            "cookies": {},
            "ports": {}
        }

        results["headers"] = HeaderScanner.scan(target)
        results["ssl"] = SSLChecker.scan(target)
        results["technologies"] = TechnologyDetector.scan(target)
        results["robots"] = RobotsChecker.scan(target)
        results["sitemap"] = SitemapChecker.scan(target)
        results["cookies"] = CookieScanner.scan(target)
        results["ports"] = PortScanner.scan(target)

        security = SecurityScore.calculate(results)

        return {
            "status": "completed",
            "security": security,
            "results": results
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
