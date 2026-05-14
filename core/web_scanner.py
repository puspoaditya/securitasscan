"""
core/web_scanner.py - Web Application Scanner
Techniques: Header analysis, Tech detection, Crawling, Form extraction
"""

import re
import time
import urllib.parse
import concurrent.futures
import ssl
import socket
from typing import Optional
import urllib.request
import urllib.error
from config import (
    DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, COMMON_DIRS,
    SECURITY_HEADERS, SERVER_SIGNATURES, Colors
)


def make_request(
    url: str,
    method: str = "GET",
    data: dict = None,
    headers: dict = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    verify_ssl: bool = False,
) -> Optional[dict]:
    """
    Generic HTTP request wrapper.
    Returns dict with status, headers, body, url.
    """
    try:
        req_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)

        # Build request
        if data and method == "POST":
            post_data = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(url, data=post_data, headers=req_headers, method="POST")
        else:
            req = urllib.request.Request(url, headers=req_headers, method=method)

        # SSL context
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(1024 * 512)  # Max 512KB
            try:
                body_text = body.decode("utf-8", errors="ignore")
            except Exception:
                body_text = ""

            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body_text,
                "url": resp.url,
                "raw_headers": {k.lower(): v for k, v in resp.headers.items()},
            }

    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": "",
            "url": url,
            "raw_headers": {},
            "error": str(e),
        }
    except Exception as e:
        return None


def check_security_headers(response: dict) -> dict:
    """Check for missing or misconfigured security headers."""
    results = {
        "missing": [],
        "present": [],
        "info_leakage": [],
        "score": 0,
    }

    raw_headers = {k.lower(): v for k, v in response.get("headers", {}).items()}

    for header, risk in SECURITY_HEADERS.items():
        if header.lower() in raw_headers:
            results["present"].append({
                "header": header,
                "value": raw_headers[header.lower()]
            })
            results["score"] += 1
        else:
            results["missing"].append({
                "header": header,
                "risk": risk,
                "severity": "MEDIUM"
            })

    # Check for information leakage headers
    for sig_header in SERVER_SIGNATURES:
        if sig_header.lower() in raw_headers:
            results["info_leakage"].append({
                "header": sig_header,
                "value": raw_headers[sig_header.lower()],
                "risk": "Reveals server technology"
            })

    return results


def detect_technologies(response: dict) -> list:
    """Fingerprint web technologies from headers and body."""
    techs = []
    headers = {k.lower(): v.lower() for k, v in response.get("headers", {}).items()}
    body = response.get("body", "").lower()

    tech_signatures = {
        # CMS
        "WordPress":    ["/wp-content/", "/wp-includes/", "wordpress"],
        "Joomla":       ["/components/com_", "joomla", "/media/jui/"],
        "Drupal":       ["drupal", "/sites/default/", "drupal.js"],
        "Magento":      ["magento", "mage/", "varien"],
        "Shopify":      ["shopify", "cdn.shopify.com", "myshopify.com"],

        # Frameworks
        "Laravel":      ["laravel_session", "laravel", "illuminate"],
        "Django":       ["csrfmiddlewaretoken", "django"],
        "Rails":        ["x-runtime", "_rails_", "rails"],
        "Express":      ["x-powered-by: express"],
        "Next.js":      ["__next", "_next/static", "next.js"],
        "React":        ["react", "__react", "data-reactroot"],
        "Vue.js":       ["vue", "__vue", "data-v-"],
        "Angular":      ["ng-version", "angular", "ng-app"],

        # Servers
        "Apache":       ["server: apache"],
        "Nginx":        ["server: nginx"],
        "IIS":          ["server: microsoft-iis", "x-aspnet-version"],
        "Cloudflare":   ["server: cloudflare", "cf-ray", "__cfduid"],
        "AWS":          ["x-amz-", "awselb", "amazonaws"],

        # Databases (exposed)
        "phpMyAdmin":   ["phpmyadmin", "pma_"],
        "Adminer":      ["adminer"],

        # Analytics
        "Google Analytics": ["google-analytics.com", "ga.js", "gtag"],
        "jQuery":           ["jquery"],
    }

    for tech, sigs in tech_signatures.items():
        for sig in sigs:
            if sig in body or sig in str(headers):
                techs.append(tech)
                break

    return list(set(techs))


def extract_forms(body: str, base_url: str) -> list:
    """Extract HTML forms for fuzzing."""
    forms = []
    form_pattern = re.compile(
        r'<form[^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL
    )
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*>',
        re.IGNORECASE
    )
    action_pattern = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)

    for match in form_pattern.finditer(body):
        form_html = match.group(0)
        inner = match.group(1)

        action_match = action_pattern.search(form_html)
        method_match = method_pattern.search(form_html)

        action = action_match.group(1) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "GET"

        # Resolve relative URLs
        if action.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif not action.startswith("http"):
            action = urllib.parse.urljoin(base_url, action)

        inputs = []
        for inp_match in input_pattern.finditer(inner):
            name = inp_match.group(1)
            inp_type = inp_match.group(2) or "text"
            inputs.append({"name": name, "type": inp_type})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def crawl_links(body: str, base_url: str) -> list:
    """Extract all links from a page."""
    links = set()
    parsed_base = urllib.parse.urlparse(base_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # href links
    for match in re.finditer(r'href=["\']([^"\'#]+)["\']', body, re.IGNORECASE):
        link = match.group(1).strip()
        if link.startswith("http"):
            if parsed_base.netloc in link:
                links.add(link)
        elif link.startswith("/"):
            links.add(base_domain + link)
        elif not link.startswith(("javascript:", "mailto:", "tel:")):
            links.add(urllib.parse.urljoin(base_url, link))

    return list(links)


def directory_fuzz(
    base_url: str,
    wordlist: list = None,
    threads: int = 20,
    callback=None,
) -> list:
    """Brute-force directory and file discovery."""
    if wordlist is None:
        wordlist = COMMON_DIRS

    base_url = base_url.rstrip("/")
    found = []

    def check_path(path):
        url = f"{base_url}/{path}"
        resp = make_request(url, timeout=3)
        if resp and resp["status"] not in (404, 400, 403):
            return {
                "url": url,
                "status": resp["status"],
                "path": path,
                "size": len(resp.get("body", "")),
            }
        # Check for soft 404 by size
        if resp and resp["status"] == 200 and len(resp.get("body", "")) < 100:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, p): p for p in wordlist}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                found.append(result)
            if callback:
                callback(i + 1, len(wordlist))

    return sorted(found, key=lambda x: x["status"])


def check_cors(url: str) -> dict:
    """Test for CORS misconfiguration."""
    test_origins = [
        "https://evil.com",
        "null",
        "https://attacker.com",
    ]
    results = []

    for origin in test_origins:
        resp = make_request(url, headers={"Origin": origin})
        if resp:
            acao = resp.get("raw_headers", {}).get("access-control-allow-origin", "")
            acac = resp.get("raw_headers", {}).get("access-control-allow-credentials", "")
            if acao:
                vuln = acao == "*" or acao == origin
                results.append({
                    "origin_sent": origin,
                    "acao_header": acao,
                    "credentials_allowed": acac.lower() == "true",
                    "vulnerable": vuln,
                })

    return {
        "results": results,
        "vulnerable": any(r["vulnerable"] for r in results),
    }


def full_web_scan(url: str, fuzz_dirs: bool = True, callback=None) -> dict:
    """Run full web recon scan on a target URL."""
    results = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "technologies": [],
        "security_headers": {},
        "forms": [],
        "links": [],
        "directories": [],
        "cors": {},
        "cookies": [],
        "server_info": {},
    }

    resp = make_request(url)
    if not resp:
        return results

    results["reachable"] = True
    results["status_code"] = resp["status"]
    results["technologies"] = detect_technologies(resp)
    results["security_headers"] = check_security_headers(resp)
    results["forms"] = extract_forms(resp["body"], url)
    results["links"] = crawl_links(resp["body"], url)

    # Extract cookies info
    cookie_header = resp.get("raw_headers", {}).get("set-cookie", "")
    if cookie_header:
        results["cookies"].append({
            "raw": cookie_header,
            "httponly": "httponly" in cookie_header.lower(),
            "secure": "secure" in cookie_header.lower(),
            "samesite": "samesite" in cookie_header.lower(),
        })

    # Server info
    for h in ["server", "x-powered-by", "x-generator"]:
        val = resp.get("raw_headers", {}).get(h)
        if val:
            results["server_info"][h] = val

    # CORS check
    results["cors"] = check_cors(url)

    # Directory fuzzing
    if fuzz_dirs:
        results["directories"] = directory_fuzz(url, callback=callback)

    return results
