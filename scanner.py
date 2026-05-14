"""
core/scanner.py - Network & Port Scanner
Techniques: TCP Connect, Banner Grabbing, Service Detection, OS Fingerprinting hints
"""

import socket
import concurrent.futures
import time
import struct
from config import DEFAULT_TIMEOUT, DEFAULT_THREADS, TOP_PORTS, Colors

# Service banner signatures
SERVICE_SIGNATURES = {
    "SSH":    ["SSH-", "OpenSSH"],
    "FTP":    ["220", "FTP", "FileZilla", "ProFTPD", "vsftpd"],
    "SMTP":   ["220", "ESMTP", "Postfix", "Sendmail", "Exchange"],
    "HTTP":   ["HTTP/", "Server:", "Apache", "nginx", "IIS"],
    "MySQL":  ["\x4a\x00\x00\x00", "mysql", "MariaDB"],
    "Redis":  ["-ERR", "+PONG", "*1\r\n"],
    "MongoDB":["MongoDB", "mongod"],
    "RDP":    ["\x03\x00"],
    "Telnet": ["\xff\xfd", "login:"],
    "VNC":    ["RFB 00"],
    "SMB":    ["\x00\x00\x00\x85\xff\x53\x4d\x42"],
}

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2181: "Zookeeper",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Grab service banner from open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Send probe based on port
        if port in (80, 8080, 8000, 8888):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner on connect
        elif port == 22:
            pass  # SSH sends banner on connect
        elif port == 25:
            s.send(b"EHLO scanner\r\n")
        elif port == 3306:
            pass  # MySQL sends greeting
        else:
            s.send(b"\r\n")

        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:200]  # Limit banner length
    except Exception:
        return ""


def detect_service(port: int, banner: str) -> str:
    """Detect service from port number and banner."""
    # Check banner signatures
    for service, sigs in SERVICE_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in banner.lower():
                return service

    # Fallback to known port mapping
    return COMMON_SERVICES.get(port, "Unknown")


def scan_port(args) -> dict | None:
    """Scan a single port. Returns result dict or None if closed."""
    ip, port, timeout, grab = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            banner = grab_banner(ip, port, timeout) if grab else ""
            service = detect_service(port, banner)
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
            }
    except Exception:
        pass
    return None


def udp_scan_port(ip: str, port: int, timeout: float = 2.0) -> dict | None:
    """Basic UDP scan (limited without root)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00" * 4, (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            return {"port": port, "state": "open|filtered", "protocol": "udp"}
        except socket.timeout:
            return {"port": port, "state": "open|filtered", "protocol": "udp"}
        except Exception:
            return None
    except Exception:
        return None
    finally:
        s.close()


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {target}")


def scan_ports(
    target: str,
    ports: list[int] = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    grab_banners: bool = True,
    port_range: tuple = None,
    callback=None,
) -> dict:
    """
    Main port scanner.
    Returns structured results with open ports, services, banners.
    """
    start_time = time.time()

    # Resolve target
    ip = resolve_target(target)

    # Determine ports to scan
    if port_range:
        ports_to_scan = list(range(port_range[0], port_range[1] + 1))
    elif ports:
        ports_to_scan = ports
    else:
        ports_to_scan = TOP_PORTS

    results = {
        "target": target,
        "ip": ip,
        "scan_time": None,
        "total_scanned": len(ports_to_scan),
        "open_ports": [],
        "os_hint": "",
    }

    # Threaded scan
    args = [(ip, port, timeout, grab_banners) for port in ports_to_scan]
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, arg): arg for arg in args}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                open_ports.append(result)
            if callback:
                callback(i + 1, len(ports_to_scan))

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    results["open_ports"] = open_ports
    results["scan_time"] = round(time.time() - start_time, 2)

    # Basic OS fingerprinting hints
    results["os_hint"] = _guess_os(open_ports)

    return results


def _guess_os(open_ports: list) -> str:
    """Rough OS guess based on open ports."""
    port_nums = {p["port"] for p in open_ports}

    if 3389 in port_nums or 135 in port_nums or 445 in port_nums:
        return "Windows (likely)"
    if 22 in port_nums and 111 in port_nums:
        return "Linux/Unix (likely)"
    if 22 in port_nums:
        return "Linux/Unix/macOS (possible)"
    return "Unknown"


def print_scan_results(results: dict):
    """Pretty print scan results to terminal."""
    c = Colors
    print(f"\n{c.CYAN}{c.BOLD}{'═'*60}{c.RESET}")
    print(f"{c.BOLD}  TARGET : {c.GREEN}{results['target']}{c.RESET} ({results['ip']})")
    print(f"{c.BOLD}  SCANNED: {results['total_scanned']} ports in {results['scan_time']}s{c.RESET}")
    print(f"{c.BOLD}  OS HINT: {c.YELLOW}{results['os_hint']}{c.RESET}")
    print(f"{c.CYAN}{'═'*60}{c.RESET}\n")

    if not results["open_ports"]:
        print(f"  {c.YELLOW}No open ports found.{c.RESET}\n")
        return

    print(f"  {'PORT':<10}{'STATE':<12}{'SERVICE':<16}{'BANNER'}")
    print(f"  {'-'*70}")
    for p in results["open_ports"]:
        banner_short = p["banner"][:40].replace("\n", " ") if p["banner"] else ""
        print(
            f"  {c.GREEN}{p['port']:<10}{c.RESET}"
            f"{c.CYAN}{'open':<12}{c.RESET}"
            f"{c.YELLOW}{p['service']:<16}{c.RESET}"
            f"{banner_short}"
        )
    print()
