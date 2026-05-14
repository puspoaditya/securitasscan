"""
core/recon.py - OSINT & Reconnaissance
Techniques: DNS enumeration, WHOIS, subdomain discovery, email harvesting
"""

import socket
import re
import json
import time
import concurrent.futures
import urllib.request
import urllib.parse
import ssl
import urllib.error
from config import Colors, DEFAULT_TIMEOUT


# Common subdomains wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "m", "api", "dev", "staging", "test", "portal", "admin", "blog",
    "shop", "forum", "help", "support", "app", "cloud", "data", "files",
    "cdn", "assets", "static", "media", "img", "images", "video", "docs",
    "dashboard", "panel", "backend", "internal", "intranet", "remote",
    "gitlab", "github", "jenkins", "jira", "confluence", "wiki", "svn",
    "monitor", "status", "health", "metrics", "grafana", "kibana",
    "mysql", "db", "database", "postgres", "redis", "elastic", "mongo",
    "old", "new", "v2", "v3", "beta", "alpha", "preview", "demo",
    "secure", "login", "auth", "sso", "oauth", "accounts", "signup",
    "mobile", "ios", "android", "download", "update", "uploads",
]


def dns_lookup(domain: str, record_types: list = None) -> dict:
    """
    Perform DNS lookups for various record types.
    Uses system resolver (no dnspython dependency).
    """
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    results = {}

    # A record (IPv4)
    if "A" in record_types:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            results["A"] = ips
        except Exception:
            results["A"] = []

    # AAAA record (IPv6)
    if "AAAA" in record_types:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
            results["AAAA"] = list(set(info[4][0] for info in infos))
        except Exception:
            results["AAAA"] = []

    # MX, NS, TXT via dig API (HackerTarget)
    for rtype in ["MX", "NS", "TXT"]:
        if rtype in record_types:
            try:
                url = f"https://api.hackertarget.com/dnslookup/?q={domain}&type={rtype}"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    data = resp.read().decode()
                    results[rtype] = [line.strip() for line in data.strip().split("\n") if line.strip()]
            except Exception:
                results[rtype] = []

    return results


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def subdomain_enum_bruteforce(
    domain: str,
    wordlist: list = None,
    threads: int = 50,
    callback=None,
) -> list:
    """Brute-force subdomain enumeration via DNS resolution."""
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    found = []

    def check_subdomain(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return {"subdomain": fqdn, "ip": ip, "source": "bruteforce"}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                found.append(result)
            if callback:
                callback(i + 1, len(wordlist))

    return sorted(found, key=lambda x: x["subdomain"])


def subdomain_enum_crtsh(domain: str) -> list:
    """
    Passive subdomain enumeration via crt.sh (Certificate Transparency).
    No bruteforce - just queries public SSL certificate logs.
    """
    found = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            "User-Agent": "SecurityScanner",
            "Accept": "application/json"
        })
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            data = json.loads(resp.read().decode())

        seen = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub.endswith(domain) and sub not in seen:
                    seen.add(sub)
                    found.append({
                        "subdomain": sub,
                        "source": "crt.sh",
                        "issued_to": entry.get("name_value", ""),
                        "issuer": entry.get("issuer_name", ""),
                    })
    except Exception as e:
        pass

    return found


def get_whois_info(domain: str) -> dict:
    """
    Basic WHOIS lookup via HackerTarget API.
    """
    try:
        url = f"https://api.hackertarget.com/whois/?q={domain}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            raw = resp.read().decode()

        # Parse key fields
        result = {"raw": raw, "parsed": {}}
        patterns = {
            "registrar":    r"Registrar:\s*(.+)",
            "created":      r"Creation Date:\s*(.+)",
            "expires":      r"Expir(?:y|ation) Date:\s*(.+)",
            "updated":      r"Updated Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "registrant":   r"Registrant(?:\s+\w+)?:\s*(.+)",
            "emails":       r"[\w.-]+@[\w.-]+\.\w+",
        }

        for field, pattern in patterns.items():
            if field == "emails":
                emails = re.findall(pattern, raw)
                result["parsed"]["emails"] = list(set(emails))
            elif field == "name_servers":
                ns_list = re.findall(pattern, raw, re.IGNORECASE)
                result["parsed"]["name_servers"] = [ns.strip() for ns in ns_list]
            else:
                match = re.search(pattern, raw, re.IGNORECASE)
                if match:
                    result["parsed"][field] = match.group(1).strip()

        return result
    except Exception as e:
        return {"error": str(e), "raw": "", "parsed": {}}


def get_ip_info(ip: str) -> dict:
    """Get geolocation and ASN info for an IP."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def check_shodan_exposure(ip: str, api_key: str = None) -> dict:
    """
    Query Shodan for exposed services on an IP.
    Requires Shodan API key for full results.
    """
    if not api_key:
        return {"error": "Shodan API key required", "tip": "Get free key at shodan.io"}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityScanner"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def google_dorks(domain: str) -> list:
    """
    Generate useful Google dork queries for a domain.
    (Manual - returns queries to paste in Google)
    """
    dorks = [
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:doc OR filetype:docx',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log',
        f'site:{domain} filetype:bak',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:upload',
        f'site:{domain} inurl:backup',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} "powered by" OR "built with"',
        f'site:{domain} intext:"error" intext:"sql"',
        f'site:{domain} intext:"ORA-" OR intext:"MySQL"',
        f'site:{domain} ext:env OR ext:cfg OR ext:conf',
        f'"@{domain}" email',
        f'inurl:"{domain}" site:pastebin.com',
        f'"{domain}" site:github.com',
        f'"{domain}" site:gitlab.com',
    ]
    return dorks


def full_recon(domain: str, brute_subdomains: bool = True, callback=None) -> dict:
    """Run full OSINT recon on a domain."""
    # Strip protocol if present
    domain = re.sub(r'^https?://', '', domain).strip("/").split("/")[0]

    results = {
        "domain": domain,
        "dns": {},
        "whois": {},
        "ip_info": {},
        "subdomains": [],
        "google_dorks": [],
        "reverse_dns": "",
    }

    # DNS
    results["dns"] = dns_lookup(domain)

    # Get primary IP info
    primary_ip = results["dns"].get("A", [""])[0]
    if primary_ip:
        results["ip_info"] = get_ip_info(primary_ip)
        results["reverse_dns"] = reverse_dns(primary_ip)

    # WHOIS
    results["whois"] = get_whois_info(domain)

    # Subdomains (passive first)
    crtsh_results = subdomain_enum_crtsh(domain)

    if brute_subdomains:
        brute_results = subdomain_enum_bruteforce(domain, callback=callback)
        # Merge, deduplicate
        seen = {r["subdomain"] for r in crtsh_results}
        for r in brute_results:
            if r["subdomain"] not in seen:
                crtsh_results.append(r)
                seen.add(r["subdomain"])

    results["subdomains"] = crtsh_results

    # Google dorks
    results["google_dorks"] = google_dorks(domain)

    return results
