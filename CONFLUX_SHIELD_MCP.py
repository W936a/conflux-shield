#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           CONFLUX SHIELD MCP SERVER v1.0                         ║
║           CONFLUX SYSTEMS (PTY) LTD — CAPE TOWN, SOUTH AFRICA    ║
╠══════════════════════════════════════════════════════════════════╣
║  PROPRIETARY AND CONFIDENTIAL                                     ║
║  © 2026 CONFLUX SYSTEMS (PTY) LTD. ALL RIGHTS RESERVED.          ║
╠══════════════════════════════════════════════════════════════════╣
║  FIXES APPLIED:                                                   ║
║  ✅ VirusTotal scan now waits 15 seconds for analysis            ║
║  ✅ check_headers uses case-insensitive matching                 ║
║  ✅ Password check tool warns about logging (not stored)         ║
╚══════════════════════════════════════════════════════════════════╝

INSTALL DEPENDENCIES:
  pip install fastapi uvicorn httpx PyJWT pydantic redis --break-system-packages

RUN:
  # HTTP mode (production)
  export SHIELD_JWT_SECRET=your_secret
  python CONFLUX_SHIELD_MCP.py

  # stdio mode (Claude Desktop)
  export SHIELD_DEFAULT_USER=user_id
  python CONFLUX_SHIELD_MCP.py --stdio

OPTIONAL API KEYS:
  export VIRUSTOTAL_API_KEY=your_key  # For malware scanning
  export NVD_API_KEY=your_key          # For CVE lookups
"""

import asyncio
import hmac
import json
import logging
import os
import re
import sqlite3
import sys
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import hashlib
import base64

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn

# Optional Redis
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# ══════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════

class Config:
    SERVER_NAME        = "conflux-shield"
    SERVER_VERSION     = "1.1.0"
    DISPLAY_NAME       = "SHIELD"
    VENDOR             = "CONFLUX SYSTEMS (PTY) LTD"
    PROTOCOL_VERSION   = "2024-11-05"

    # Auth
    JWT_SECRET         = os.getenv("SHIELD_JWT_SECRET")
    API_KEY            = os.getenv("SHIELD_API_KEY")

    # Database
    DB_PATH            = os.getenv("SHIELD_DB_PATH", "./shield.db")

    # Redis
    REDIS_URL          = os.getenv("REDIS_URL", "")

    # Server
    PORT               = int(os.getenv("PORT", "8085"))
    HOST               = os.getenv("HOST", "0.0.0.0")

    # Rate limits
    RATE_LIMIT_DEFAULT = int(os.getenv("RATE_LIMIT_DEFAULT", "60"))
    RATE_LIMIT_WRITE   = int(os.getenv("RATE_LIMIT_WRITE", "30"))

    # External APIs
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    NVD_API_KEY        = os.getenv("NVD_API_KEY", "")

    @classmethod
    def validate(cls):
        if not cls.JWT_SECRET and not cls.API_KEY:
            raise ValueError("SHIELD_JWT_SECRET or SHIELD_API_KEY is required")

config = Config()

# ══════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SHIELD] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger("conflux.shield")

# ══════════════════════════════════════════════════════════════
# RATE LIMITER
# ══════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self):
        self.redis = None
        self._local_windows: Dict[str, deque] = defaultdict(deque)

    async def connect(self):
        if config.REDIS_URL and REDIS_AVAILABLE:
            try:
                self.redis = await redis.from_url(config.REDIS_URL, decode_responses=True)
                log.info("Redis rate limiter connected")
                return
            except Exception as e:
                log.warning(f"Redis connection failed: {e}")
        log.info("Using in-memory rate limiter")

    async def check(self, key: str, limit: int, window_seconds: int = 60) -> Tuple[bool, int]:
        if self.redis:
            now = time.time()
            window_start = now - window_seconds
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, window_seconds)
            results = await pipe.execute()
            count = results[1]
            if count >= limit:
                return False, 0
            return True, limit - count - 1
        else:
            now = time.time()
            window = self._local_windows[key]
            while window and window[0] < now - window_seconds:
                window.popleft()
            if len(window) >= limit:
                return False, 0
            window.append(now)
            return True, limit - len(window)

    def get_key(self, client_id: str, tool: str) -> str:
        return f"ratelimit:shield:{client_id}:{tool}"

rate_limiter = RateLimiter()

# ══════════════════════════════════════════════════════════════
# SECURITY PATTERNS
# ══════════════════════════════════════════════════════════════

SQL_INJECTION_PATTERNS = [
    (r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b", "SQL Keyword Sequence"),
    (r"--", "SQL Comment"),
    (r";\s*(DROP|DELETE|UPDATE|INSERT)", "SQL Command Chaining"),
    (r"\bOR\s+1\s*=\s*1\b", "Boolean Injection"),
    (r"\bOR\s+'\w+'\s*=\s*'\w+'\b", "String Injection"),
    (r"\bUNION\s+SELECT\b", "Union Attack"),
    (r"\bWAITFOR\s+DELAY\b", "Time-based Injection"),
    (r"';\s*(DROP|DELETE|UPDATE|INSERT)", "Quote Termination"),
]

XSS_PATTERNS = [
    (r"<script.*?>.*?</script>", "Script Tag"),
    (r"javascript:", "JavaScript Protocol"),
    (r"on\w+\s*=", "Event Handler"),
    (r"<iframe.*?>", "Iframe Injection"),
    (r"<img.*?onerror=", "Image Error XSS"),
    (r"<body.*?onload=", "Body Load XSS"),
    (r"eval\s*\(.*?\)", "Eval Execution"),
    (r"document\.cookie", "Cookie Stealing"),
    (r"alert\s*\(.*?\)", "Alert Popup"),
]

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey|api_key)\s*=\s*['\"]?[a-zA-Z0-9]{16,64}['\"]?", "API Key"),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"]?[^'\"]{8,}['\"]?", "Password"),
    (r"(?i)(secret|token|jwt|bearer)\s*=\s*['\"]?[a-zA-Z0-9._-]{16,}['\"]?", "Secret Token"),
    (r"(?i)sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"(?i)ghp_[a-zA-Z0-9]{36}", "GitHub Token"),
    (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
    (r"(?i)-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
    (r"(?i)-----BEGIN OPENSSH PRIVATE KEY-----", "SSH Private Key"),
]

PASSWORD_PATTERNS = [
    (r".{8,}", "Minimum length (8+ characters)"),
    (r"[A-Z]", "Uppercase letter"),
    (r"[a-z]", "Lowercase letter"),
    (r"[0-9]", "Number"),
    (r"[!@#$%^&*(),.?\":{}|<>]", "Special character"),
]

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS header",
    "Content-Security-Policy": "Missing CSP header",
    "X-Frame-Options": "Missing clickjacking protection",
    "X-Content-Type-Options": "Missing MIME type protection",
    "X-XSS-Protection": "Missing XSS protection",
    "Referrer-Policy": "Missing referrer policy"
}

# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════

class ShieldDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                findings TEXT,
                severity TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                cached_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()
        log.info(f"Database initialized at {self.db_path}")

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        finally:
            conn.close()

    def save_scan(self, user_id: str, scan_type: str, target: str, findings: List[Dict], severity: str) -> str:
        scan_id = str(uuid.uuid4())[:8]
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history (id, user_id, scan_type, target, findings, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (scan_id, user_id, scan_type, target, json.dumps(findings), severity))
            conn.commit()
        return scan_id

    def get_scan_history(self, user_id: str, limit: int = 50) -> List[Dict]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, scan_type, target, findings, severity, timestamp
                FROM scan_history
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit))
            rows = cursor.fetchall()
        return [{
            "id": r[0], "type": r[1], "target": r[2],
            "findings": json.loads(r[3]), "severity": r[4], "timestamp": r[5]
        } for r in rows]

    def cache_cve(self, cve_id: str, data: Dict):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cve_cache (cve_id, data, cached_at)
                VALUES (?, ?, ?)
            """, (cve_id, json.dumps(data), datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_cached_cve(self, cve_id: str) -> Optional[Dict]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM cve_cache WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None

    def delete_all_data(self, user_id: str, confirm: bool = False) -> Dict:
        if not confirm:
            return {"error": "Delete all requires confirm=True"}
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
            deleted = cursor.rowcount
            conn.commit()
        return {"deleted": deleted, "message": f"Deleted {deleted} scan records"}

db = ShieldDB(config.DB_PATH)

# ══════════════════════════════════════════════════════════════
# SCANNERS
# ══════════════════════════════════════════════════════════════

def scan_sql_injection(text: str) -> List[Dict]:
    findings = []
    for pattern, name in SQL_INJECTION_PATTERNS:
        if re.search(pattern, text):
            findings.append({
                "type": "SQL_INJECTION",
                "pattern": name,
                "severity": "HIGH",
                "description": f"Potential SQL injection detected: {name}"
            })
    return findings

def scan_xss(text: str) -> List[Dict]:
    findings = []
    for pattern, name in XSS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "XSS",
                "pattern": name,
                "severity": "HIGH",
                "description": f"Potential XSS vulnerability: {name}"
            })
    return findings

def scan_secrets(text: str) -> List[Dict]:
    findings = []
    for pattern, name in SECRET_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings.append({
                "type": "HARDCODED_SECRET",
                "pattern": name,
                "severity": "CRITICAL",
                "description": f"Hardcoded secret detected: {name}"
            })
    return findings

def check_password_strength(password: str) -> Dict:
    score = 0
    checks = []
    for pattern, name in PASSWORD_PATTERNS:
        if re.search(pattern, password):
            score += 1
            checks.append({"passed": True, "check": name})
        else:
            checks.append({"passed": False, "check": name})

    if score >= 5:
        strength = "STRONG"
    elif score >= 3:
        strength = "MODERATE"
    elif score >= 1:
        strength = "WEAK"
    else:
        strength = "VERY_WEAK"

    return {
        "strength": strength,
        "score": score,
        "checks": checks,
        "message": "Password is " + strength.lower()
    }

def scan_code(code: str, language: str = "unknown") -> List[Dict]:
    findings = []
    findings.extend(scan_sql_injection(code))
    findings.extend(scan_xss(code))
    findings.extend(scan_secrets(code))

    if language.lower() in ["python", "py"]:
        if re.search(r"\beval\s*\(", code):
            findings.append({
                "type": "DANGEROUS_FUNCTION",
                "pattern": "eval()",
                "severity": "HIGH",
                "description": "Use of eval() can lead to code injection"
            })
        if re.search(r"\bexec\s*\(", code):
            findings.append({
                "type": "DANGEROUS_FUNCTION",
                "pattern": "exec()",
                "severity": "HIGH",
                "description": "Use of exec() can lead to code injection"
            })
        if re.search(r"pickle\.loads", code):
            findings.append({
                "type": "INSECURE_DESERIALIZATION",
                "pattern": "pickle",
                "severity": "HIGH",
                "description": "Pickle deserialization can execute arbitrary code"
            })

    elif language.lower() in ["javascript", "js"]:
        if re.search(r"\beval\s*\(", code):
            findings.append({
                "type": "DANGEROUS_FUNCTION",
                "pattern": "eval()",
                "severity": "HIGH",
                "description": "Use of eval() can lead to code injection"
            })
        if re.search(r"innerHTML\s*=", code):
            findings.append({
                "type": "XSS_RISK",
                "pattern": "innerHTML",
                "severity": "MEDIUM",
                "description": "Using innerHTML can lead to XSS if not sanitized"
            })

    return findings

async def scan_url(url: str) -> Dict:
    """Scan URL with VirusTotal — FIXED: wait for analysis"""
    if not config.VIRUSTOTAL_API_KEY:
        return {
            "url": url,
            "status": "API_KEY_REQUIRED",
            "message": "VirusTotal API key not configured"
        }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Submit URL
            submit_resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY}
            )
            if submit_resp.status_code != 200:
                return {"url": url, "error": "Submission failed"}

            submit_data = submit_resp.json()
            scan_id = submit_data.get("data", {}).get("id", "")

            # FIXED: Wait for VirusTotal to process (5-30 seconds typical)
            await asyncio.sleep(15)

            # Get analysis results
            analysis_resp = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY}
            )
            if analysis_resp.status_code != 200:
                return {"url": url, "error": "Analysis failed"}

            data = analysis_resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return {
                "url": url,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "is_safe": malicious == 0 and suspicious == 0,
                "scan_date": data.get("data", {}).get("attributes", {}).get("date")
            }
    except Exception as e:
        log.error(f"VirusTotal scan failed: {e}")
        return {"url": url, "error": str(e)}

async def lookup_cve(cve_id: str) -> Dict:
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return {"error": "Invalid CVE format. Must start with CVE-YYYY-XXXX"}

    cached = db.get_cached_cve(cve_id)
    if cached:
        return cached

    if not config.NVD_API_KEY:
        return {
            "cve_id": cve_id,
            "status": "API_KEY_REQUIRED",
            "message": "NVD API key not configured"
        }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers={"apiKey": config.NVD_API_KEY}
            )
            if resp.status_code != 200:
                return {"cve_id": cve_id, "error": "CVE not found or API error"}

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return {"cve_id": cve_id, "error": "CVE not found"}

            cve_data = vulnerabilities[0].get("cve", {})
            metrics = cve_data.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})

            result = {
                "cve_id": cve_id,
                "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "cvss_v3_score": cvss_v3.get("baseScore"),
                "cvss_v3_severity": cvss_v3.get("baseSeverity"),
                "cvss_v2_score": cvss_v2.get("baseScore"),
                "cvss_v2_severity": cvss_v2.get("severity"),
                "references": [ref.get("url") for ref in cve_data.get("references", [])[:5]]
            }

            db.cache_cve(cve_id, result)
            return result
    except Exception as e:
        log.error(f"CVE lookup failed: {e}")
        return {"cve_id": cve_id, "error": str(e)}

def check_security_headers(headers: Dict[str, str]) -> List[Dict]:
    """Check HTTP security headers — FIXED: case-insensitive matching"""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, message in REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append({
                "type": "MISSING_SECURITY_HEADER",
                "header": header,
                "severity": "MEDIUM",
                "description": message
            })

    # Additional check for HSTS max-age
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts and "max-age=31536000" not in hsts:
        findings.append({
            "type": "WEAK_HSTS",
            "header": "Strict-Transport-Security",
            "severity": "MEDIUM",
            "description": "HSTS should have max-age=31536000 (1 year)"
        })

    return findings

# ══════════════════════════════════════════════════════════════
# ADDITIONAL SECURITY CHECKS (v1.1)
# ══════════════════════════════════════════════════════════════

PATH_TRAVERSAL_PATTERNS = [
    (r"\.\./", "Directory Traversal"),
    (r"\.\./\.\./", "Deep Directory Traversal"),
    (r"%2e%2e%2f", "URL-Encoded Traversal"),
    (r"etc/passwd", "Sensitive File Access"),
    (r"etc/shadow", "Shadow File Access"),
    (r"proc/self/environ", "Environment File Access"),
    (r"win/system32", "Windows System Access"),
]

SSRF_PATTERNS = [
    (r"(?i)http://localhost", "SSRF localhost"),
    (r"(?i)http://127\.0\.0\.1", "SSRF Loopback"),
    (r"(?i)http://0\.0\.0\.0", "SSRF Wildcard"),
    (r"(?i)http://169\.254\.169\.254", "AWS Metadata SSRF"),
    (r"(?i)http://192\.168\.", "SSRF Private Range"),
    (r"(?i)http://10\.", "SSRF Private Range"),
]

KNOWN_VULNERABLE_DEPS = {
    "log4j": {"severity": "CRITICAL", "cve": "CVE-2021-44228", "description": "Log4Shell RCE vulnerability"},
    "log4j2": {"severity": "CRITICAL", "cve": "CVE-2021-44228", "description": "Log4Shell RCE vulnerability"},
    "struts2": {"severity": "CRITICAL", "cve": "CVE-2017-5638", "description": "Apache Struts2 RCE"},
    "shellshock": {"severity": "CRITICAL", "cve": "CVE-2014-6271", "description": "Shellshock bash vulnerability"},
    "heartbleed": {"severity": "CRITICAL", "cve": "CVE-2014-0160", "description": "OpenSSL Heartbleed"},
    "requests==2.6.0": {"severity": "HIGH", "cve": "CVE-2018-18074", "description": "Requests credential exposure"},
    "django==1.": {"severity": "HIGH", "cve": "Multiple", "description": "Outdated Django — multiple CVEs"},
    "flask==0.": {"severity": "MEDIUM", "cve": "Multiple", "description": "Outdated Flask version"},
    "node_modules/lodash@4.17.1": {"severity": "HIGH", "cve": "CVE-2021-23337", "description": "Lodash prototype pollution"},
    "serialize-javascript": {"severity": "HIGH", "cve": "CVE-2020-7660", "description": "XSS via serialized data"},
}

def scan_path_traversal(text: str) -> List[Dict]:
    findings = []
    for pattern, name in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "PATH_TRAVERSAL",
                "pattern": name,
                "severity": "HIGH",
                "description": f"Path traversal attempt detected: {name}"
            })
    return findings

def scan_ssrf(text: str) -> List[Dict]:
    findings = []
    for pattern, name in SSRF_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append({
                "type": "SSRF",
                "pattern": name,
                "severity": "HIGH",
                "description": f"Server-Side Request Forgery risk: {name}"
            })
    return findings

def check_file_hash(content: str, expected_hash: str, algorithm: str = "sha256") -> Dict:
    content_bytes = content.encode("utf-8") if isinstance(content, str) else content
    if algorithm == "sha256":
        actual = hashlib.sha256(content_bytes).hexdigest()
    elif algorithm == "sha1":
        actual = hashlib.sha1(content_bytes).hexdigest()
    elif algorithm == "md5":
        actual = hashlib.md5(content_bytes).hexdigest()
    else:
        return {"error": f"Unsupported algorithm: {algorithm}"}
    match = hmac.compare_digest(actual.lower(), expected_hash.lower())
    return {
        "algorithm": algorithm,
        "expected": expected_hash.lower(),
        "actual": actual,
        "match": match,
        "verdict": "VERIFIED" if match else "TAMPERED"
    }

def scan_dependencies(requirements_text: str) -> List[Dict]:
    findings = []
    lines = requirements_text.lower().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for dep, info in KNOWN_VULNERABLE_DEPS.items():
            if dep.lower() in line:
                findings.append({
                    "type": "VULNERABLE_DEPENDENCY",
                    "dependency": line,
                    "matched_pattern": dep,
                    "severity": info["severity"],
                    "cve": info["cve"],
                    "description": info["description"]
                })
    return findings

# ══════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════

class ScanCodeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=100000)
    language: str = Field("unknown", max_length=50)

class ScanTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000)

class CheckPasswordRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)

class ScanUrlRequest(BaseModel):
    url: str = Field(..., max_length=500)

class LookupCVERequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$", max_length=20)

class CheckHeadersRequest(BaseModel):
    headers: Dict[str, str] = Field(..., description="HTTP headers as key-value pairs")

class DeleteAllRequest(BaseModel):
    confirm: bool = Field(False, description="Must be true to delete all data")

class CheckHashRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=1000000)
    expected_hash: str = Field(..., min_length=32, max_length=128)
    algorithm: str = Field("sha256", pattern="^(sha256|sha1|md5)$")

class ScanDepsRequest(BaseModel):
    requirements: str = Field(..., min_length=1, max_length=50000, description="requirements.txt or package.json content")

class GenerateReportRequest(BaseModel):
    code: Optional[str] = Field(None, max_length=100000)
    text: Optional[str] = Field(None, max_length=50000)
    headers: Optional[Dict[str, str]] = None
    language: str = Field("unknown", max_length=50)

# ══════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════

async def get_current_user(authorization: str = Header(default="")) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    if authorization.startswith("Bearer "):
        token = authorization[7:]
        if not config.JWT_SECRET:
            raise HTTPException(status_code=401, detail="JWT not configured")
        try:
            payload = jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token: missing subject")
            return user_id
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    else:
        if not config.API_KEY:
            raise HTTPException(status_code=401, detail="API key not configured")
        if not hmac.compare_digest(authorization, config.API_KEY):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return "api_user"

# ══════════════════════════════════════════════════════════════
# MCP TOOL IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════

async def tool_scan_code(user_id: str, code: str, language: str = "unknown") -> Dict:
    findings = scan_code(code, language)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    scan_id = db.save_scan(user_id, "code", f"{language}: {len(code)} chars", findings,
                           "HIGH" if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0 else "MEDIUM")

    return {
        "scan_id": scan_id,
        "findings": findings,
        "summary": severity_counts,
        "total_findings": len(findings),
        "recommendation": "Fix all CRITICAL and HIGH severity findings before deployment."
    }

async def tool_scan_text(user_id: str, text: str) -> Dict:
    findings = []
    findings.extend(scan_sql_injection(text))
    findings.extend(scan_xss(text))
    findings.extend(scan_secrets(text))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    scan_id = db.save_scan(user_id, "text", f"{len(text)} chars", findings,
                           "HIGH" if severity_counts["CRITICAL"] > 0 or severity_counts["HIGH"] > 0 else "LOW")

    return {
        "scan_id": scan_id,
        "findings": findings,
        "summary": severity_counts,
        "total_findings": len(findings)
    }

async def tool_check_password(user_id: str, password: str) -> Dict:
    """Check password strength. NOTE: Passwords are not stored in logs or database."""
    return check_password_strength(password)

async def tool_scan_url(user_id: str, url: str) -> Dict:
    result = await scan_url(url)
    if "error" not in result:
        severity = "HIGH" if result.get("malicious", 0) > 0 else "LOW"
        db.save_scan(user_id, "url", url, [result] if result.get("malicious", 0) > 0 else [], severity)
    return result

async def tool_lookup_cve(user_id: str, cve_id: str) -> Dict:
    result = await lookup_cve(cve_id)
    if "error" not in result:
        severity = "HIGH" if result.get("cvss_v3_score", 0) >= 7.0 else "MEDIUM"
        db.save_scan(user_id, "cve", cve_id, [result], severity)
    return result

async def tool_check_headers(user_id: str, headers: Dict[str, str]) -> Dict:
    findings = check_security_headers(headers)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    scan_id = db.save_scan(user_id, "headers", f"{len(headers)} headers", findings,
                           "MEDIUM" if severity_counts["MEDIUM"] > 0 else "LOW")

    return {
        "scan_id": scan_id,
        "findings": findings,
        "summary": severity_counts,
        "recommendation": "Add missing security headers to improve security posture."
    }

async def tool_get_scan_history(user_id: str, limit: int = 50) -> Dict:
    history = db.get_scan_history(user_id, limit)
    return {"scans": history, "count": len(history)}

async def tool_delete_all_data(user_id: str, confirm: bool = False) -> Dict:
    return db.delete_all_data(user_id, confirm)

async def tool_check_hash(user_id: str, content: str, expected_hash: str, algorithm: str = "sha256") -> Dict:
    """Verify file/content integrity by comparing hashes"""
    result = check_file_hash(content, expected_hash, algorithm)
    severity = "CRITICAL" if not result.get("match") else "LOW"
    db.save_scan(user_id, "hash", f"{algorithm}:{expected_hash[:16]}...", [result] if not result.get("match") else [], severity)
    return result

async def tool_scan_advanced(user_id: str, text: str) -> Dict:
    """Advanced scan: SQL injection, XSS, secrets, path traversal, SSRF"""
    findings = []
    findings.extend(scan_sql_injection(text))
    findings.extend(scan_xss(text))
    findings.extend(scan_secrets(text))
    findings.extend(scan_path_traversal(text))
    findings.extend(scan_ssrf(text))

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    overall = "CRITICAL" if severity_counts["CRITICAL"] > 0 else "HIGH" if severity_counts["HIGH"] > 0 else "MEDIUM" if severity_counts["MEDIUM"] > 0 else "LOW"
    scan_id = db.save_scan(user_id, "advanced_text", f"{len(text)} chars", findings, overall)

    return {
        "scan_id": scan_id,
        "findings": findings,
        "summary": severity_counts,
        "total_findings": len(findings),
        "overall_severity": overall
    }

async def tool_scan_dependencies(user_id: str, requirements: str) -> Dict:
    """Scan requirements.txt or package.json for known vulnerable dependencies"""
    findings = scan_dependencies(requirements)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    overall = "CRITICAL" if severity_counts["CRITICAL"] > 0 else "HIGH" if severity_counts["HIGH"] > 0 else "LOW"
    scan_id = db.save_scan(user_id, "dependencies", f"{len(requirements.splitlines())} packages", findings, overall)

    return {
        "scan_id": scan_id,
        "findings": findings,
        "summary": severity_counts,
        "total_findings": len(findings),
        "recommendation": "Update all vulnerable dependencies immediately." if findings else "No known vulnerabilities detected."
    }

async def tool_generate_security_report(user_id: str, code: str = None, text: str = None,
                                         headers: Dict = None, language: str = "unknown") -> Dict:
    """Generate a comprehensive security report covering all scan types in one call"""
    report = {"sections": [], "total_findings": 0, "overall_severity": "LOW", "generated_at": datetime.now(timezone.utc).isoformat()}
    all_findings = []

    if code:
        code_findings = scan_code(code, language)
        all_findings.extend(code_findings)
        report["sections"].append({"type": "code", "language": language, "findings": code_findings, "count": len(code_findings)})

    if text:
        text_findings = []
        text_findings.extend(scan_sql_injection(text))
        text_findings.extend(scan_xss(text))
        text_findings.extend(scan_secrets(text))
        text_findings.extend(scan_path_traversal(text))
        text_findings.extend(scan_ssrf(text))
        all_findings.extend(text_findings)
        report["sections"].append({"type": "text", "findings": text_findings, "count": len(text_findings)})

    if headers:
        header_findings = check_security_headers(headers)
        all_findings.extend(header_findings)
        report["sections"].append({"type": "headers", "findings": header_findings, "count": len(header_findings)})

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    overall = "CRITICAL" if severity_counts["CRITICAL"] > 0 else "HIGH" if severity_counts["HIGH"] > 0 else "MEDIUM" if severity_counts["MEDIUM"] > 0 else "LOW"
    report["summary"] = severity_counts
    report["total_findings"] = len(all_findings)
    report["overall_severity"] = overall
    report["recommendation"] = (
        "URGENT: Fix CRITICAL findings before deployment." if severity_counts["CRITICAL"] > 0 else
        "HIGH priority issues found. Address before production." if severity_counts["HIGH"] > 0 else
        "Review MEDIUM findings. Consider fixing before deployment." if severity_counts["MEDIUM"] > 0 else
        "No significant issues found. Good security posture."
    )

    db.save_scan(user_id, "full_report", "comprehensive", all_findings, overall)
    return report

# ══════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ══════════════════════════════════════════════════════════════

TOOLS = {
    "scan_code": {
        "name": "scan_code",
        "description": "Scan code for security vulnerabilities (SQL injection, XSS, hardcoded secrets)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Code to scan"},
                "language": {"type": "string", "description": "Programming language (python, javascript, etc.)", "default": "unknown"}
            },
            "required": ["code"]
        },
        "handler": tool_scan_code
    },
    "scan_text": {
        "name": "scan_text",
        "description": "Scan text for SQL injection, XSS, and hardcoded secrets",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to scan"}},
            "required": ["text"]
        },
        "handler": tool_scan_text
    },
    "check_password": {
        "name": "check_password",
        "description": "Check password strength and provide feedback. Passwords are not stored.",
        "inputSchema": {
            "type": "object",
            "properties": {"password": {"type": "string"}},
            "required": ["password"]
        },
        "handler": tool_check_password
    },
    "scan_url": {
        "name": "scan_url",
        "description": "Scan URL with VirusTotal for malware (requires API key). Analysis takes ~15 seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"]
        },
        "handler": tool_scan_url
    },
    "lookup_cve": {
        "name": "lookup_cve",
        "description": "Look up CVE details from NVD database",
        "inputSchema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,}$"}},
            "required": ["cve_id"]
        },
        "handler": tool_lookup_cve
    },
    "check_headers": {
        "name": "check_headers",
        "description": "Check HTTP security headers for missing security controls",
        "inputSchema": {
            "type": "object",
            "properties": {"headers": {"type": "object", "additionalProperties": {"type": "string"}}},
            "required": ["headers"]
        },
        "handler": tool_check_headers
    },
    "get_scan_history": {
        "name": "get_scan_history",
        "description": "Get previous scan history",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "default": 50}}
        },
        "handler": tool_get_scan_history
    },
    "delete_all_data": {
        "name": "delete_all_data",
        "description": "Delete ALL scan history for this user. Requires confirm=true",
        "inputSchema": {
            "type": "object",
            "properties": {"confirm": {"type": "boolean", "default": False}},
            "required": ["confirm"]
        },
        "handler": tool_delete_all_data
    },
    "check_hash": {
        "name": "check_hash",
        "description": "Verify file or content integrity by comparing SHA-256/SHA-1/MD5 hashes. Detects tampering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "File content to hash"},
                "expected_hash": {"type": "string", "description": "Expected hash to compare against"},
                "algorithm": {"type": "string", "enum": ["sha256", "sha1", "md5"], "default": "sha256"}
            },
            "required": ["content", "expected_hash"]
        },
        "handler": tool_check_hash
    },
    "scan_advanced": {
        "name": "scan_advanced",
        "description": "Advanced text scan covering SQL injection, XSS, secrets, path traversal, and SSRF — 5 attack vectors in one call.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text or input to scan"}},
            "required": ["text"]
        },
        "handler": tool_scan_advanced
    },
    "scan_dependencies": {
        "name": "scan_dependencies",
        "description": "Scan requirements.txt or package.json content for known vulnerable dependencies (Log4Shell, Shellshock, etc.)",
        "inputSchema": {
            "type": "object",
            "properties": {"requirements": {"type": "string", "description": "requirements.txt or package.json content"}},
            "required": ["requirements"]
        },
        "handler": tool_scan_dependencies
    },
    "generate_security_report": {
        "name": "generate_security_report",
        "description": "Generate a comprehensive security report covering code, text, and headers in one call. Returns overall severity and actionable recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Code to scan (optional)"},
                "text": {"type": "string", "description": "Text/input to scan (optional)"},
                "headers": {"type": "object", "description": "HTTP headers to check (optional)"},
                "language": {"type": "string", "default": "unknown"}
            }
        },
        "handler": tool_generate_security_report
    }
}

# ══════════════════════════════════════════════════════════════
# MCP MESSAGE HANDLER
# ══════════════════════════════════════════════════════════════

async def handle_mcp_message(message: Dict, user_id: str) -> Dict:
    msg_id = message.get("id")
    method = message.get("method", "")
    params = message.get("params", {})

    def ok(result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(code, msg, data=None):
        error = {"code": code, "message": msg}
        if data:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": msg_id, "error": error}

    try:
        if method == "initialize":
            return ok({
                "protocolVersion": config.PROTOCOL_VERSION,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": config.SERVER_NAME, "version": config.SERVER_VERSION, "vendor": config.VENDOR}
            })
        elif method in ("initialized", "ping"):
            return ok({})
        elif method == "tools/list":
            return ok({"tools": [{"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]} for t in TOOLS.values()]})
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name not in TOOLS:
                return err(-32601, f"Tool not found: {tool_name}")

            try:
                if tool_name == "scan_code":
                    validated = ScanCodeRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "scan_text":
                    validated = ScanTextRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "check_password":
                    validated = CheckPasswordRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "scan_url":
                    validated = ScanUrlRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "lookup_cve":
                    validated = LookupCVERequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "check_headers":
                    validated = CheckHeadersRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "delete_all_data":
                    validated = DeleteAllRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "check_hash":
                    validated = CheckHashRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "scan_advanced":
                    validated = ScanTextRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "scan_dependencies":
                    validated = ScanDepsRequest(**tool_args)
                    args = validated.model_dump()
                elif tool_name == "generate_security_report":
                    validated = GenerateReportRequest(**tool_args)
                    args = validated.model_dump()
                else:
                    args = tool_args
            except Exception as e:
                return err(-32602, f"Invalid arguments: {e}")

            tool_limit = config.RATE_LIMIT_WRITE if tool_name in ["delete_all_data"] else config.RATE_LIMIT_DEFAULT
            key = rate_limiter.get_key(user_id, tool_name)
            allowed, _ = await rate_limiter.check(key, tool_limit)
            if not allowed:
                return err(-32000, "Rate limit exceeded")

            result = await TOOLS[tool_name]["handler"](user_id, **args)
            return ok({
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": "error" in result
            })
        else:
            return err(-32601, f"Method not found: {method}")
    except Exception as e:
        log.error(f"MCP handler error: {e}", exc_info=True)
        return err(-32603, "Internal error", {"detail": str(e)})

# ══════════════════════════════════════════════════════════════
# FASTAPI APP
# ══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    await rate_limiter.connect()
    log.info(f"{config.DISPLAY_NAME} v{config.SERVER_VERSION} ready")
    if config.VIRUSTOTAL_API_KEY:
        log.info("VirusTotal integration enabled (15s analysis wait)")
    if config.NVD_API_KEY:
        log.info("NVD CVE lookup enabled")
    yield
    log.info(f"{config.DISPLAY_NAME} shutting down")

app = FastAPI(title=config.DISPLAY_NAME, version=config.SERVER_VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.get("/health")
async def health():
    return {
        "status": "online",
        "service": config.DISPLAY_NAME,
        "version": config.SERVER_VERSION,
        "vendor": config.VENDOR,
        "features": {
            "virustotal": bool(config.VIRUSTOTAL_API_KEY),
            "nvd": bool(config.NVD_API_KEY)
        }
    }

@app.get("/")
async def root():
    return {"name": config.DISPLAY_NAME, "version": config.SERVER_VERSION, "vendor": config.VENDOR, "tools": list(TOOLS.keys())}

@app.post("/mcp")
async def mcp_endpoint(request: Request, user_id: str = Depends(get_current_user)):
    client_id = request.client.host if request.client else "unknown"
    allowed, _ = await rate_limiter.check(rate_limiter.get_key(client_id, "mcp"), config.RATE_LIMIT_DEFAULT)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    response = await handle_mcp_message(body, user_id)
    return JSONResponse(content=response)

# ══════════════════════════════════════════════════════════════
# STDIO TRANSPORT
# ══════════════════════════════════════════════════════════════

async def run_stdio():
    log.info(f"{config.DISPLAY_NAME} — stdio mode")
    await rate_limiter.connect()

    user_id = os.getenv("SHIELD_DEFAULT_USER")
    if not user_id:
        log.error("SHIELD_DEFAULT_USER not set for stdio mode")
        sys.exit(1)

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as e:
                error_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {e}"}}
                sys.stdout.write(json.dumps(error_resp) + "\n")
                sys.stdout.flush()
                continue
            response = await handle_mcp_message(message, user_id)
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        except asyncio.CancelledError:
            break
        except Exception as e:
            error_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}
            sys.stdout.write(json.dumps(error_resp) + "\n")
            sys.stdout.flush()

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    try:
        config.validate()
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    args = sys.argv[1:]

    if "--stdio" in args:
        asyncio.run(run_stdio())
    else:
        port = config.PORT
        for i, arg in enumerate(args):
            if arg == "--port" and i + 1 < len(args):
                port = int(args[i + 1])

        print(f"\n{'='*60}")
        print(f"  {config.DISPLAY_NAME} MCP v{config.SERVER_VERSION}")
        print(f"  {config.VENDOR}")
        print(f"{'='*60}")
        print(f"  HTTP:      http://0.0.0.0:{port}")
        print(f"  MCP:       http://0.0.0.0:{port}/mcp")
        print(f"  Health:    http://0.0.0.0:{port}/health")
        print(f"  Tools:     {', '.join(TOOLS.keys())}")
        print(f"  Features:  SQL injection detection")
        print(f"             XSS vulnerability scanning")
        print(f"             Hardcoded secret detection")
        print(f"             Password strength checking")
        print(f"             URL malware scanning (VirusTotal, 15s wait)")
        print(f"             CVE lookup (NVD)")
        print(f"             Security headers validation (case-insensitive)")
        print(f"             SQLite WAL mode")
        print(f"             Confirm required for delete")
        print(f"{'='*60}\n")

        uvicorn.run(app, host=config.HOST, port=port, log_level="info")

if __name__ == "__main__":
    main()