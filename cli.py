#!/usr/bin/env python3
"""
cli.py - SecuritasScan Command Line Interface
Usage: python cli.py [module] [options]
"""

import sys
import os
import argparse
import json
import time
import threading

# Fix Unicode output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(__file__))

from config import Colors, VERSION, TOOL_NAME, TOP_PORTS
c = Colors


BANNER = f"""
{c.CYAN}{c.BOLD}
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗ █████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝██╔══██╗██╔════╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║   ███████║███████╗
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║   ██╔══██║╚════██║
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║   ██║  ██║███████║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
{c.RESET}{c.YELLOW}
          All-in-One Security Scanner v{VERSION} | For Authorized Testing Only
{c.RESET}"""


def print_banner():
    print(BANNER)


def progress_bar(current, total, prefix="Progress", width=40):
    filled = int(width * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (width - filled)
    pct = 100 * current / total if total > 0 else 0
    print(f"\r  {prefix}: [{c.CYAN}{bar}{c.RESET}] {pct:.0f}%", end="", flush=True)
    if current >= total:
        print()


def print_section(title: str):
    print(f"\n{c.CYAN}{c.BOLD}{'─'*60}{c.RESET}")
    print(f"{c.BOLD}  {title}{c.RESET}")
    print(f"{c.CYAN}{'─'*60}{c.RESET}")


def print_vuln(vuln: dict):
    sev_colors = {
        "CRITICAL": c.RED,
        "HIGH": c.RED,
        "MEDIUM": c.YELLOW,
        "LOW": c.CYAN,
        "INFO": c.WHITE,
    }
    sev = vuln.get("severity", "INFO")
    col = sev_colors.get(sev, c.WHITE)
    print(f"  {col}[{sev}]{c.RESET} {vuln.get('type', '?')}")
    print(f"         Payload : {c.YELLOW}{vuln.get('payload', 'N/A')[:80]}{c.RESET}")
    print(f"         Evidence: {vuln.get('evidence', vuln.get('details', 'N/A'))[:100]}")
    print()


# ─────────────────────────────────
# Sub-command handlers
# ─────────────────────────────────

def cmd_portscan(args):
    from core.scanner import scan_ports, print_scan_results

    print_section(f"Port Scanner → {args.target}")
    print(f"  Mode    : {args.scan_type}")
    print(f"  Threads : {args.threads}")

    if args.scan_type == "top":
        ports = TOP_PORTS
    elif args.scan_type == "full":
        ports = list(range(1, 65536))
    elif args.scan_type == "custom" and args.ports:
        ports = [int(p) for p in args.ports.split(",")]
    else:
        ports = TOP_PORTS

    print(f"  Ports   : {len(ports)} to scan\n")

    results = scan_ports(
        target=args.target,
        ports=ports,
        threads=args.threads,
        grab_banners=not args.no_banners,
        callback=lambda cur, tot: progress_bar(cur, tot, "Scanning"),
    )

    print_scan_results(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"  {c.GREEN}Results saved to {args.output}{c.RESET}")


def cmd_webscan(args):
    from core.web_scanner import full_web_scan

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    print_section(f"Web Scanner → {url}")

    results = full_web_scan(
        url=url,
        fuzz_dirs=not args.no_fuzz,
        callback=lambda cur, tot: progress_bar(cur, tot, "Fuzzing"),
    )

    if not results["reachable"]:
        print(f"  {c.RED}Target unreachable.{c.RESET}")
        return

    print(f"\n  Status      : {c.GREEN}{results['status_code']}{c.RESET}")
    print(f"  Technologies: {c.YELLOW}{', '.join(results['technologies']) or 'None detected'}{c.RESET}")

    # Security headers
    headers_result = results["security_headers"]
    missing = headers_result.get("missing", [])
    print(f"\n  Security Headers: {c.GREEN}{len(headers_result.get('present', []))} present{c.RESET}, {c.RED}{len(missing)} missing{c.RESET}")
    for h in missing:
        print(f"    {c.RED}✗{c.RESET} {h['header']} — {h['risk']}")

    # Info leakage
    leaks = headers_result.get("info_leakage", [])
    if leaks:
        print(f"\n  {c.YELLOW}Info Leakage Headers:{c.RESET}")
        for l in leaks:
            print(f"    {c.YELLOW}⚠{c.RESET}  {l['header']}: {l['value']}")

    # Cookies
    for cookie in results.get("cookies", []):
        flags = []
        if not cookie["httponly"]:
            flags.append(f"{c.RED}Missing HttpOnly{c.RESET}")
        if not cookie["secure"]:
            flags.append(f"{c.YELLOW}Missing Secure{c.RESET}")
        if flags:
            print(f"\n  Cookie Issues: {', '.join(flags)}")

    # CORS
    cors = results.get("cors", {})
    if cors.get("vulnerable"):
        print(f"\n  {c.RED}[HIGH] CORS Misconfiguration detected!{c.RESET}")

    # Directories
    dirs = results.get("directories", [])
    if dirs:
        print(f"\n  Discovered Paths ({len(dirs)}):")
        for d in dirs:
            status_col = c.GREEN if d["status"] == 200 else c.YELLOW
            print(f"    {status_col}[{d['status']}]{c.RESET} {d['url']}")

    # Forms
    forms = results.get("forms", [])
    if forms:
        print(f"\n  Forms Found ({len(forms)}):")
        for form in forms:
            print(f"    [{form['method']}] {form['action']} — {len(form['inputs'])} fields")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  {c.GREEN}Results saved to {args.output}{c.RESET}")


def cmd_sqli(args):
    from modules.sqli import scan_url_params, scan_forms
    from core.web_scanner import make_request, extract_forms

    url = args.url
    print_section(f"SQL Injection Scanner → {url}")

    resp = make_request(url)
    forms = extract_forms(resp["body"], url) if resp else []

    print(f"  Testing URL params...")
    param_vulns = scan_url_params(url)

    print(f"  Testing {len(forms)} forms...")
    form_vulns = scan_forms(url, forms)

    all_vulns = param_vulns + form_vulns
    total = sum(len(r.get("vulnerabilities", [])) for r in all_vulns)

    if total == 0:
        print(f"\n  {c.GREEN}✓ No SQLi vulnerabilities detected.{c.RESET}")
    else:
        print(f"\n  {c.RED}Found {total} SQLi vulnerability(ies):{c.RESET}\n")
        for result in all_vulns:
            for vuln in result.get("vulnerabilities", []):
                print(f"  Parameter: {c.YELLOW}{result['parameter']}{c.RESET}")
                print_vuln(vuln)


def cmd_xss(args):
    from modules.vuln_testers import scan_url_for_xss, scan_forms_for_xss
    from core.web_scanner import make_request, extract_forms

    url = args.url
    print_section(f"XSS Scanner → {url}")

    resp = make_request(url)
    forms = extract_forms(resp["body"], url) if resp else []

    param_vulns = scan_url_for_xss(url)
    form_vulns = scan_forms_for_xss(url, forms)

    all_vulns = param_vulns + form_vulns
    total = sum(len(r.get("vulnerabilities", [])) for r in all_vulns)

    if total == 0:
        print(f"\n  {c.GREEN}✓ No XSS vulnerabilities detected.{c.RESET}")
    else:
        print(f"\n  {c.RED}Found {total} XSS vulnerability(ies):{c.RESET}\n")
        for result in all_vulns:
            for vuln in result.get("vulnerabilities", []):
                print(f"  Parameter: {c.YELLOW}{result['parameter']}{c.RESET}")
                print_vuln(vuln)


def cmd_lfi(args):
    from modules.vuln_testers import scan_url_for_lfi

    url = args.url
    print_section(f"LFI Scanner → {url}")

    results = scan_url_for_lfi(url)
    total = sum(len(r.get("vulnerabilities", [])) for r in results)

    if total == 0:
        print(f"\n  {c.GREEN}✓ No LFI vulnerabilities detected.{c.RESET}")
    else:
        print(f"\n  {c.RED}Found {total} LFI vulnerability(ies):{c.RESET}\n")
        for result in results:
            for vuln in result.get("vulnerabilities", []):
                print(f"  Parameter: {c.YELLOW}{result['parameter']}{c.RESET}")
                print_vuln(vuln)


def cmd_ssl(args):
    from modules.vuln_testers import check_ssl

    hostname = args.hostname.replace("https://", "").replace("http://", "").split("/")[0]
    print_section(f"SSL/TLS Checker → {hostname}")

    result = check_ssl(hostname, args.port)

    grade_color = c.GREEN if result["grade"] == "A" else (c.YELLOW if result["grade"] in ("B","C") else c.RED)
    print(f"\n  Grade    : {grade_color}{c.BOLD}{result['grade']}{c.RESET}")
    print(f"  Protocol : {result.get('protocol', 'N/A')}")
    print(f"  Cipher   : {result.get('cipher', 'N/A')} ({result.get('cipher_bits', '?')} bits)")

    cert = result.get("certificate", {})
    if cert:
        print(f"\n  Certificate:")
        print(f"    Subject : {cert.get('subject', {}).get('commonName', 'N/A')}")
        print(f"    Issuer  : {cert.get('issuer', {}).get('organizationName', 'N/A')}")
        print(f"    Expires : {cert.get('expires', 'N/A')} ({cert.get('days_remaining', '?')} days left)")
        san = cert.get("san", [])
        if san:
            print(f"    SANs    : {', '.join(san[:5])}")

    vulns = result.get("vulnerabilities", [])
    if vulns:
        print(f"\n  {c.RED}Vulnerabilities:{c.RESET}")
        for v in vulns:
            print_vuln(v)
    else:
        print(f"\n  {c.GREEN}✓ No SSL/TLS issues found.{c.RESET}")


def cmd_recon(args):
    from core.recon import full_recon

    print_section(f"OSINT Recon → {args.domain}")

    results = full_recon(
        args.domain,
        brute_subdomains=not args.no_brute,
        callback=lambda cur, tot: progress_bar(cur, tot, "Subdomain enum"),
    )

    dns = results.get("dns", {})
    print(f"\n  DNS Records:")
    for rtype, values in dns.items():
        if values:
            print(f"    {c.YELLOW}{rtype:<8}{c.RESET} {', '.join(str(v) for v in values[:5])}")

    ip_info = results.get("ip_info", {})
    if ip_info:
        print(f"\n  IP Info ({ip_info.get('ip', 'N/A')}):")
        print(f"    Location : {ip_info.get('city', '?')}, {ip_info.get('country_name', '?')}")
        print(f"    ASN      : {ip_info.get('asn', '?')} — {ip_info.get('org', '?')}")

    whois = results.get("whois", {}).get("parsed", {})
    if whois:
        print(f"\n  WHOIS:")
        for k, v in whois.items():
            if v and k != "emails":
                print(f"    {k:<16}: {str(v)[:60]}")
        emails = whois.get("emails", [])
        if emails:
            print(f"    Emails found : {', '.join(emails[:5])}")

    subs = results.get("subdomains", [])
    print(f"\n  Subdomains Found ({len(subs)}):")
    for sub in subs[:20]:
        print(f"    {c.GREEN}{sub['subdomain']}{c.RESET} ({sub.get('ip', sub.get('source', '?'))})")
    if len(subs) > 20:
        print(f"    ... and {len(subs)-20} more")

    dorks = results.get("google_dorks", [])
    if dorks:
        print(f"\n  Google Dorks (paste in Google):")
        for d in dorks[:8]:
            print(f"    {c.CYAN}{d}{c.RESET}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  {c.GREEN}Results saved to {args.output}{c.RESET}")


def cmd_binary(args):
    from core.binary_analyzer import analyze_file, print_analysis

    print_section(f"Binary Analysis → {args.file}")

    if not os.path.isfile(args.file):
        print(f"  {c.RED}File not found: {args.file}{c.RESET}")
        return

    result = analyze_file(args.file)
    print_analysis(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n  {c.GREEN}Results saved to {args.output}{c.RESET}")


def cmd_full(args):
    """Run all applicable scans."""
    target = args.target
    url = target if target.startswith("http") else f"http://{target}"
    domain = url.replace("http://","").replace("https://","").split("/")[0]

    print_section(f"Full Scan → {target}")

    # Recon
    print(f"\n  {c.CYAN}[1/5] Running OSINT Recon...{c.RESET}")
    class FakeArgs:
        pass
    recon_args = FakeArgs()
    recon_args.domain = domain
    recon_args.no_brute = True
    recon_args.output = None
    cmd_recon(recon_args)

    # Port scan
    print(f"\n  {c.CYAN}[2/5] Port Scanning...{c.RESET}")
    port_args = FakeArgs()
    port_args.target = domain
    port_args.scan_type = "top"
    port_args.ports = None
    port_args.threads = 50
    port_args.no_banners = False
    port_args.output = None
    cmd_portscan(port_args)

    # Web scan
    print(f"\n  {c.CYAN}[3/5] Web Scanning...{c.RESET}")
    web_args = FakeArgs()
    web_args.url = url
    web_args.no_fuzz = False
    web_args.output = None
    cmd_webscan(web_args)

    # Vuln scans
    print(f"\n  {c.CYAN}[4/5] SQLi + XSS + LFI Testing...{c.RESET}")
    for cmd, arg_url in [(cmd_sqli, url), (cmd_xss, url), (cmd_lfi, url)]:
        vuln_args = FakeArgs()
        vuln_args.url = arg_url
        cmd(vuln_args)

    # SSL
    print(f"\n  {c.CYAN}[5/5] SSL/TLS Check...{c.RESET}")
    ssl_args = FakeArgs()
    ssl_args.hostname = domain
    ssl_args.port = 443
    cmd_ssl(ssl_args)


# ─────────────────────────────────
# Main
# ─────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Module")

    # Port scan
    ps = subparsers.add_parser("portscan", help="Network port scanner")
    ps.add_argument("target", help="IP or hostname")
    ps.add_argument("--scan-type", choices=["top", "full", "custom"], default="top")
    ps.add_argument("--ports", help="Comma-separated ports (for --scan-type custom)")
    ps.add_argument("--threads", type=int, default=50)
    ps.add_argument("--no-banners", action="store_true")
    ps.add_argument("-o", "--output", help="Save JSON results to file")

    # Web scan
    ws = subparsers.add_parser("webscan", help="Web application scanner")
    ws.add_argument("url", help="Target URL")
    ws.add_argument("--no-fuzz", action="store_true", help="Skip directory fuzzing")
    ws.add_argument("-o", "--output")

    # SQLi
    sq = subparsers.add_parser("sqli", help="SQL injection tester")
    sq.add_argument("url", help="Target URL with GET params")
    sq.add_argument("-o", "--output")

    # XSS
    xp = subparsers.add_parser("xss", help="XSS tester")
    xp.add_argument("url", help="Target URL with GET params")

    # LFI
    lp = subparsers.add_parser("lfi", help="LFI/RFI tester")
    lp.add_argument("url", help="Target URL with file-like params")

    # SSL
    sp = subparsers.add_parser("ssl", help="SSL/TLS analyzer")
    sp.add_argument("hostname", help="Hostname (no protocol)")
    sp.add_argument("--port", type=int, default=443)

    # Recon
    rp = subparsers.add_parser("recon", help="OSINT reconnaissance")
    rp.add_argument("domain", help="Target domain")
    rp.add_argument("--no-brute", action="store_true", help="Skip subdomain bruteforce")
    rp.add_argument("-o", "--output")

    # Binary
    bp = subparsers.add_parser("binary", help="Static binary analysis")
    bp.add_argument("file", help="Path to binary file")
    bp.add_argument("-o", "--output")

    # Full scan
    fp = subparsers.add_parser("full", help="Run all scans on a target")
    fp.add_argument("target", help="IP, hostname, or URL")

    # API server
    ap = subparsers.add_parser("server", help="Start Web UI API server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    dispatch = {
        "portscan": cmd_portscan,
        "webscan":  cmd_webscan,
        "sqli":     cmd_sqli,
        "xss":      cmd_xss,
        "lfi":      cmd_lfi,
        "ssl":      cmd_ssl,
        "recon":    cmd_recon,
        "binary":   cmd_binary,
        "full":     cmd_full,
    }

    if args.command == "server":
        from api.server import create_app
        app = create_app()
        if app:
            print(f"  {c.GREEN}Starting API server on http://{args.host}:{args.port}{c.RESET}")
            print(f"  {c.YELLOW}Open web/index.html in your browser{c.RESET}\n")
            app.run(host=args.host, port=args.port, debug=False, threaded=True)
    elif args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
