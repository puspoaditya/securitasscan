"""
modules/xss.py - XSS Tester
modules/lfi.py - LFI/RFI Tester
modules/ssl_checker.py - SSL/TLS Analyzer
"""

import re
import ssl
import socket
import datetime
import urllib.parse
from core.web_scanner import make_request
from config import XSS_PAYLOADS, LFI_PAYLOADS, LFI_INDICATORS, Colors


# ─────────────────────────────────────────
# XSS Tester
# ─────────────────────────────────────────

def test_xss_parameter(url: str, param: str, method: str = "GET", base_data: dict = None) -> dict:
    """Test a parameter for reflected XSS."""
    result = {
        "url": url,
        "parameter": param,
        "vulnerabilities": [],
    }
    base_data = base_data or {}

    for payload in XSS_PAYLOADS:
        if method == "POST":
            data = {**base_data, param: payload}
            resp = make_request(url, method="POST", data=data)
        else:
            parsed = urllib.parse.urlparse(url)
            qp = dict(urllib.parse.parse_qsl(parsed.query))
            qp[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(qp)).geturl()
            resp = make_request(test_url)

        if not resp:
            continue

        body = resp.get("body", "")

        # Check if payload is reflected unencoded in response
        if payload in body:
            # Check if it's inside a tag context
            csp = resp.get("raw_headers", {}).get("content-security-policy", "")
            result["vulnerabilities"].append({
                "type": "Reflected XSS",
                "payload": payload,
                "severity": "HIGH",
                "csp_present": bool(csp),
                "details": f"Payload reflected unencoded in response body",
            })
        # Check for partial reflection (tag stripped but content present)
        elif payload.replace("<", "").replace(">", "").replace('"', "") in body:
            result["vulnerabilities"].append({
                "type": "Possible XSS (partial reflection)",
                "payload": payload,
                "severity": "MEDIUM",
                "details": "Payload partially reflected; some sanitization in place",
            })

    return result


def scan_url_for_xss(url: str) -> list:
    """Scan all GET params in URL for XSS."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    results = []
    for param in params:
        r = test_xss_parameter(url, param)
        if r["vulnerabilities"]:
            results.append(r)
    return results


def scan_forms_for_xss(url: str, forms: list) -> list:
    """Test form fields for XSS."""
    results = []
    for form in forms:
        action = form["action"]
        method = form["method"]
        text_inputs = [i for i in form["inputs"] if i["type"] not in ("submit", "button", "file")]
        for inp in text_inputs:
            base_data = {i["name"]: "test" for i in form["inputs"]}
            r = test_xss_parameter(action, inp["name"], method=method, base_data=base_data)
            if r["vulnerabilities"]:
                results.append(r)
    return results


# ─────────────────────────────────────────
# LFI / RFI Tester
# ─────────────────────────────────────────

def test_lfi_parameter(url: str, param: str) -> dict:
    """Test a parameter for Local File Inclusion."""
    result = {
        "url": url,
        "parameter": param,
        "vulnerabilities": [],
    }

    parsed = urllib.parse.urlparse(url)

    for payload in LFI_PAYLOADS:
        qp = dict(urllib.parse.parse_qsl(parsed.query))
        qp[param] = payload
        test_url = parsed._replace(query=urllib.parse.urlencode(qp)).geturl()
        resp = make_request(test_url)

        if not resp:
            continue

        body = resp.get("body", "").lower()

        for indicator in LFI_INDICATORS:
            if indicator.lower() in body:
                result["vulnerabilities"].append({
                    "type": "Local File Inclusion (LFI)",
                    "payload": payload,
                    "indicator": indicator,
                    "severity": "CRITICAL",
                    "details": f"System file content visible in response: '{indicator}'",
                })
                break

    return result


def scan_url_for_lfi(url: str) -> list:
    """Scan all GET params for LFI."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    # LFI most likely on params like: file, page, include, path, template, view
    lfi_likely_params = {"file", "page", "include", "path", "template", "view",
                         "load", "read", "fetch", "dir", "url", "filename", "doc"}
    results = []
    for param in params:
        # Test all params, but flag likely ones
        r = test_lfi_parameter(url, param)
        r["lfi_likely_param"] = param.lower() in lfi_likely_params
        if r["vulnerabilities"]:
            results.append(r)
    return results


# ─────────────────────────────────────────
# SSL/TLS Analyzer
# ─────────────────────────────────────────

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "MD5", "SHA1", "CBC",
]

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def check_ssl(hostname: str, port: int = 443) -> dict:
    """Comprehensive SSL/TLS certificate and configuration check."""
    result = {
        "hostname": hostname,
        "port": port,
        "certificate": {},
        "protocol": "",
        "cipher": "",
        "vulnerabilities": [],
        "grade": "A",
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        result["protocol"] = protocol
        result["cipher"] = cipher[0] if cipher else ""
        result["cipher_bits"] = cipher[2] if cipher else 0

        # Parse certificate
        if cert:
            # Expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires": not_after,
                    "days_remaining": days_left,
                    "expired": days_left < 0,
                    "expiring_soon": 0 <= days_left <= 30,
                    "san": [v for _, v in cert.get("subjectAltName", [])],
                    "serial": cert.get("serialNumber", ""),
                }

                if days_left < 0:
                    result["vulnerabilities"].append({
                        "type": "Expired Certificate",
                        "severity": "CRITICAL",
                        "details": f"Certificate expired {abs(days_left)} days ago",
                    })
                elif days_left <= 30:
                    result["vulnerabilities"].append({
                        "type": "Expiring Certificate",
                        "severity": "MEDIUM",
                        "details": f"Certificate expires in {days_left} days",
                    })

        # Weak protocol check
        if protocol in WEAK_PROTOCOLS:
            result["vulnerabilities"].append({
                "type": f"Weak Protocol: {protocol}",
                "severity": "HIGH",
                "details": f"{protocol} is deprecated and insecure",
            })
            result["grade"] = "F"

        # Weak cipher check
        cipher_name = cipher[0] if cipher else ""
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                result["vulnerabilities"].append({
                    "type": f"Weak Cipher: {cipher_name}",
                    "severity": "HIGH",
                    "details": f"Cipher suite contains weak algorithm: {weak}",
                })
                result["grade"] = "C"
                break

        # Check for self-signed
        if result["certificate"]:
            subj = result["certificate"].get("subject", {})
            issuer = result["certificate"].get("issuer", {})
            if subj.get("commonName") == issuer.get("commonName"):
                result["vulnerabilities"].append({
                    "type": "Self-Signed Certificate",
                    "severity": "MEDIUM",
                    "details": "Certificate is self-signed, not trusted by browsers",
                })

        # Grade adjustment
        if not result["vulnerabilities"]:
            result["grade"] = "A"
        elif any(v["severity"] == "CRITICAL" for v in result["vulnerabilities"]):
            result["grade"] = "F"
        elif any(v["severity"] == "HIGH" for v in result["vulnerabilities"]):
            result["grade"] = "C"

    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
        result["grade"] = "F"
        result["vulnerabilities"].append({
            "type": "SSL Connection Failed",
            "severity": "CRITICAL",
            "details": str(e),
        })
    except Exception as e:
        result["error"] = str(e)

    return result
