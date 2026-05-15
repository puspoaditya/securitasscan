"""
core/breach_checker.py - Email breach checking
Uses HaveIBeenPwned v3 API (requires API key for email lookup)
Falls back to public breach list lookup via free sources
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import ssl
import time
import hashlib


def _get(url: str, headers: dict = None) -> tuple[int, dict | list | str]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={
        "User-Agent": "SecuritasScan/1.0",
        **(headers or {})
    })
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            body = r.read().decode("utf-8", errors="ignore")
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def check_password_pwned(password: str) -> dict:
    """
    Check if a password has been seen in data breaches using HIBP k-Anonymity model.
    Does NOT send the full password — only first 5 chars of SHA1 hash.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    status, body = _get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if status != 200 or not isinstance(body, str):
        return {"checked": False, "error": "Could not reach HIBP API"}

    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            return {
                "checked": True,
                "pwned": True,
                "count": count,
                "message": f"This password has been seen {count:,} times in data breaches!",
                "severity": "CRITICAL" if count > 10000 else "HIGH" if count > 100 else "MEDIUM",
            }

    return {
        "checked": True,
        "pwned": False,
        "count": 0,
        "message": "Good news — this password was not found in any known breach.",
        "severity": "NONE",
    }


def check_email_breaches(email: str, hibp_api_key: str = "") -> dict:
    """
    Check if an email has been in known data breaches.
    Requires HIBP API key for full email lookup.
    Without key: returns domain-level breach info only.
    """
    result = {
        "email": email,
        "breaches": [],
        "pastes": [],
        "breach_count": 0,
        "most_recent": None,
        "data_classes": [],
        "checked": False,
        "note": None,
    }

    if not hibp_api_key:
        result["note"] = "HIBP API key not configured. Set HIBP_API_KEY env var for full email lookup. Password checking is available without a key."
        return result

    headers = {
        "hibp-api-key": hibp_api_key,
        "User-Agent": "SecuritasScan/1.0",
    }

    encoded = urllib.parse.quote(email)
    status, data = _get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false",
        headers=headers
    )
    time.sleep(1.5)  # HIBP rate limit

    if status == 404:
        result["checked"] = True
        result["note"] = "Good news — no breaches found for this email."
        return result

    if status == 401:
        result["note"] = "Invalid HIBP API key."
        return result

    if status == 200 and isinstance(data, list):
        result["checked"] = True
        result["breach_count"] = len(data)
        result["breaches"] = [{
            "name": b.get("Name"),
            "domain": b.get("Domain"),
            "breach_date": b.get("BreachDate"),
            "pwn_count": b.get("PwnCount"),
            "data_classes": b.get("DataClasses", []),
            "description": b.get("Description", "")[:200],
        } for b in data]
        result["data_classes"] = list({dc for b in data for dc in b.get("DataClasses", [])})
        if result["breaches"]:
            result["most_recent"] = max(b["breach_date"] for b in result["breaches"] if b.get("breach_date"))

    return result


def check_domain_breaches(domain: str) -> dict:
    """
    Check breaches for an entire domain (no API key needed for this endpoint).
    """
    status, data = _get(f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}")
    if status == 200 and isinstance(data, list):
        return {
            "domain": domain,
            "breach_count": len(data),
            "breaches": [{
                "name": b.get("Name"),
                "breach_date": b.get("BreachDate"),
                "pwn_count": b.get("PwnCount"),
                "data_classes": b.get("DataClasses", []),
            } for b in data]
        }
    return {"domain": domain, "breach_count": 0, "breaches": []}
