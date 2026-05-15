"""
core/cve_lookup.py - CVE Lookup via NVD API v2
Queries NIST National Vulnerability Database for known CVEs
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time
import ssl

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map technology names to NVD-friendly search keywords
TECH_KEYWORDS = {
    "magento":        ["Magento"],
    "wordpress":      ["WordPress"],
    "drupal":         ["Drupal"],
    "joomla":         ["Joomla"],
    "jquery":         ["jQuery"],
    "apache":         ["Apache HTTP Server"],
    "nginx":          ["nginx"],
    "iis":            ["Microsoft IIS"],
    "asp.net":        ["ASP.NET"],
    "php":            ["PHP"],
    "laravel":        ["Laravel"],
    "react":          ["React"],
    "angular":        ["Angular"],
    "vue":            ["Vue.js"],
    "bootstrap":      ["Bootstrap"],
    "openssl":        ["OpenSSL"],
    "mysql":          ["MySQL"],
    "postgresql":     ["PostgreSQL"],
    "redis":          ["Redis"],
    "mongodb":        ["MongoDB"],
    "elasticsearch":  ["Elasticsearch"],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


def _nvd_request(keyword: str, results_per_page: int = 5) -> list:
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    })
    url = f"{NVD_API}?{params}"
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuritasScan/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            data = json.loads(r.read().decode())
            return data.get("vulnerabilities", [])
    except Exception:
        return []


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "N/A")
    published = cve.get("published", "")[:10]

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description.")

    # CVSS score
    metrics = cve.get("metrics", {})
    score, severity, vector = None, "NONE", ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0].get("cvssData", {})
            score = m.get("baseScore")
            severity = m.get("baseSeverity", metrics[key][0].get("baseSeverity", "NONE"))
            vector = m.get("vectorString", "")
            break

    # References
    refs = [r["url"] for r in cve.get("references", [])[:3]]

    return {
        "id": cve_id,
        "published": published,
        "description": desc[:300],
        "score": score,
        "severity": severity.upper() if severity else "NONE",
        "vector": vector,
        "references": refs,
    }


def lookup_cves(technologies: list, max_per_tech: int = 5) -> dict:
    """
    Given a list of detected technologies, return CVEs grouped by technology.
    """
    results = {}

    for tech in technologies:
        tech_lower = tech.lower().strip()

        # Match against known keyword map
        keywords = None
        for key, kws in TECH_KEYWORDS.items():
            if key in tech_lower or tech_lower in key:
                keywords = kws
                break

        if not keywords:
            keywords = [tech]

        all_cves = []
        for kw in keywords:
            raw = _nvd_request(kw, max_per_tech)
            for item in raw:
                parsed = _parse_cve(item)
                all_cves.append(parsed)
            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key

        # Dedupe by CVE ID, sort by severity
        seen = set()
        unique = []
        for c in all_cves:
            if c["id"] not in seen:
                seen.add(c["id"])
                unique.append(c)

        unique.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 4), -(x["score"] or 0)))
        results[tech] = unique[:max_per_tech]

    return results


def lookup_cves_for_server(server_header: str) -> list:
    """
    Parse a Server: header value and look up CVEs.
    e.g. 'Microsoft-IIS/10.0' → search 'Microsoft IIS 10.0'
    """
    keyword = server_header.replace("-", " ").replace("/", " ")
    raw = _nvd_request(keyword, 5)
    return [_parse_cve(i) for i in raw]
