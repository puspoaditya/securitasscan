"""
core/subdomain_takeover.py - Subdomain Takeover Detection
Checks if subdomains point to services that no longer exist (dangling CNAME)
"""

import socket
import urllib.request
import urllib.error
import ssl
import concurrent.futures

# Fingerprints: service → (CNAME pattern, HTTP response pattern, severity)
TAKEOVER_FINGERPRINTS = [
    ("github",        ["github.io"],                    ["There isn't a GitHub Pages site here", "404 - File or directory not found"], "HIGH"),
    ("heroku",        ["herokuapp.com", "heroku.com"],  ["No such app", "herokucdn.com/error-pages/no-such-app"], "HIGH"),
    ("aws_s3",        ["s3.amazonaws.com", "s3-website"], ["NoSuchBucket", "The specified bucket does not exist"], "HIGH"),
    ("azure",         ["azurewebsites.net", "cloudapp.net"], ["404 Web Site not found", "This web app is stopped"], "HIGH"),
    ("fastly",        ["fastly.net"],                   ["Fastly error: unknown domain"], "HIGH"),
    ("shopify",       ["myshopify.com"],                ["Sorry, this shop is currently unavailable"], "MEDIUM"),
    ("tumblr",        ["tumblr.com"],                   ["Whatever you were looking for doesn't currently exist"], "MEDIUM"),
    ("zendesk",       ["zendesk.com"],                  ["Help Center Closed", "Oops, this help center no longer exists"], "MEDIUM"),
    ("cargo",         ["cargocollective.com"],          ["If you're moving your domain away from Cargo"], "MEDIUM"),
    ("bitbucket",     ["bitbucket.io"],                 ["Repository not found"], "MEDIUM"),
    ("ghost",         ["ghost.io"],                     ["The thing you were looking for is no longer here"], "LOW"),
    ("surge",         ["surge.sh"],                     ["project not found"], "MEDIUM"),
    ("pantheon",      ["pantheonsite.io"],              ["The gods are wise, but do not know of the site which you seek"], "MEDIUM"),
    ("readme",        ["readme.io"],                    ["Project doesnt exist... yet!"], "LOW"),
    ("statuspage",    ["statuspage.io"],                ["Better Status Communication"], "LOW"),
]

TIMEOUT = 5


def _resolve_cname(domain: str) -> str | None:
    try:
        import socket
        return socket.getfqdn(domain)
    except Exception:
        return None


def _http_body(url: str) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0"}, method="GET"
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.read(4096).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    except Exception:
        return ""


def check_subdomain_takeover(subdomain: str) -> dict:
    result = {
        "subdomain": subdomain,
        "vulnerable": False,
        "service": None,
        "severity": None,
        "evidence": None,
        "cname": None,
    }

    # Resolve CNAME
    cname = _resolve_cname(subdomain)
    if cname and cname != subdomain:
        result["cname"] = cname

    # Check if subdomain resolves at all
    try:
        socket.gethostbyname(subdomain)
        resolves = True
    except socket.gaierror:
        resolves = False

    # Only check fingerprints if CNAME points to a known service
    target_str = (cname or "").lower()

    for service, cname_patterns, body_patterns, severity in TAKEOVER_FINGERPRINTS:
        matched_cname = any(p in target_str for p in cname_patterns)
        if not matched_cname:
            continue

        # CNAME matches — now check HTTP response
        body = _http_body(f"http://{subdomain}")
        if not body:
            body = _http_body(f"https://{subdomain}")

        for bp in body_patterns:
            if bp.lower() in body.lower():
                result["vulnerable"] = True
                result["service"] = service
                result["severity"] = severity
                result["evidence"] = bp
                return result

    return result


def scan_subdomain_takeover(subdomains: list, threads: int = 20) -> list:
    """
    Check a list of subdomains for takeover vulnerability.
    Returns only vulnerable ones.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_subdomain_takeover, s["subdomain"] if isinstance(s, dict) else s): s for s in subdomains}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r["vulnerable"]:
                results.append(r)
    results.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["severity"], 3))
    return results
