"""
core/shodan_lookup.py - Shodan host lookup via InternetDB (no API key needed)
InternetDB: https://internetdb.shodan.io/ — free, no auth, returns ports/vulns/tags
"""

import urllib.request
import urllib.error
import socket
import json
import ssl


def _get(url: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuritasScan/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "No data found for this IP"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}


def lookup_host(target: str) -> dict:
    """
    Query Shodan InternetDB for a host (IP or domain).
    No API key required. Returns open ports, CVEs, tags, hostnames.
    """
    # Resolve domain to IP
    ip = target
    hostname = None
    if not _is_ip(target):
        try:
            ip = socket.gethostbyname(target)
            hostname = target
        except socket.gaierror:
            return {"error": f"Cannot resolve {target}"}

    data = _get(f"https://internetdb.shodan.io/{ip}")
    if "error" in data:
        return {"ip": ip, "hostname": hostname, **data}

    result = {
        "ip": data.get("ip", ip),
        "hostname": hostname,
        "hostnames": data.get("hostnames", []),
        "ports": data.get("ports", []),
        "cpes": data.get("cpes", []),
        "vulns": data.get("vulns", []),
        "tags": data.get("tags", []),
    }

    # Enrich: pull CVE severity from NVD for each vuln
    result["vuln_count"] = len(result["vulns"])
    result["open_port_count"] = len(result["ports"])
    return result


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
