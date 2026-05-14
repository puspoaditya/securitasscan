# SecuritasScan — All-in-One Security Toolkit

> For **authorized penetration testing only**.
> Do NOT use on systems you don't own or have written permission to test.

---

## 📁 Structure

```
security-toolkit/
├── cli.py                  # CLI entry point (all modules)
├── config.py               # Payloads, wordlists, settings
├── requirements.txt
├── core/
│   ├── scanner.py          # TCP port scanner + banner grabbing
│   ├── web_scanner.py      # Web app recon (headers, forms, dirs, CORS)
│   ├── recon.py            # OSINT: DNS, WHOIS, subdomains, IP info
│   └── binary_analyzer.py  # Static analysis: strings, entropy, PE/ELF headers
├── modules/
│   ├── sqli.py             # SQL Injection (error-based, boolean, time-based)
│   └── vuln_testers.py     # XSS, LFI/RFI, SSL/TLS checker
├── api/
│   └── server.py           # Flask REST API (backend for Web UI)
└── web/
    └── index.html          # Web dashboard UI
```

---

## ⚡ Installation

```bash
# 1. Python 3.10+ required
python3 --version

# 2. Install dependencies (only Flask for Web UI)
pip install -r requirements.txt --break-system-packages

# 3. Run CLI directly (no extra deps needed)
python cli.py --help
```

---

## 🖥️ CLI Usage

### Port Scanner
```bash
# Top 25 common ports
python cli.py portscan 192.168.1.1

# Full TCP scan (1-65535), slower
python cli.py portscan 192.168.1.1 --scan-type full --threads 100

# Custom ports with output
python cli.py portscan target.com --scan-type custom --ports 80,443,8080,3306 -o results.json
```

### Web App Scanner
```bash
python cli.py webscan https://target.com

# Skip directory fuzzing (faster)
python cli.py webscan https://target.com --no-fuzz -o web_results.json
```

### SQL Injection
```bash
python cli.py sqli "https://target.com/search?q=test&id=1"
```

### XSS Tester
```bash
python cli.py xss "https://target.com/page?name=hello"
```

### LFI/RFI Tester
```bash
python cli.py lfi "https://target.com/view?file=home"
```

### SSL/TLS Checker
```bash
python cli.py ssl target.com
python cli.py ssl target.com --port 8443
```

### OSINT Recon
```bash
# Full recon with subdomain bruteforce
python cli.py recon target.com

# Passive only (crt.sh, DNS, WHOIS)
python cli.py recon target.com --no-brute -o recon.json
```

### Binary Analysis
```bash
python cli.py binary /path/to/suspicious.exe -o analysis.json
python cli.py binary /path/to/malware.elf
```

### Full Scan (all modules)
```bash
python cli.py full target.com
```

---

## 🌐 Web UI

```bash
# 1. Start API server
python cli.py server

# 2. Open browser → open web/index.html
# OR open http://localhost:5000 (serves via Flask)
```

---

## 🔌 API Endpoints

All return `{"job_id": "..."}` immediately. Poll with GET `/api/jobs/{job_id}`.

| Method | Endpoint | Body |
|--------|----------|------|
| GET    | /api/health | — |
| GET    | /api/jobs/{id} | — |
| POST   | /api/scan/ports | `{target, scan_type, threads}` |
| POST   | /api/scan/web | `{url, fuzz_dirs}` |
| POST   | /api/scan/sqli | `{url}` |
| POST   | /api/scan/xss | `{url}` |
| POST   | /api/scan/lfi | `{url}` |
| POST   | /api/scan/ssl | `{hostname, port}` |
| POST   | /api/scan/recon | `{domain, brute_subdomains}` |
| POST   | /api/scan/binary | multipart file upload |
| POST   | /api/scan/full | `{target}` |

---

## 🧪 Techniques Implemented

### Port Scanner
- TCP Connect scan (no root needed)
- Service banner grabbing
- Multi-threaded (configurable)
- OS fingerprinting hints
- UDP probe support

### Web Scanner
- Security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- Technology fingerprinting (CMS, frameworks, CDN)
- Cookie security flags (HttpOnly, Secure, SameSite)
- CORS misconfiguration detection
- HTML form extraction
- Directory/file bruteforcing
- Link crawling

### SQLi Module
- Error-based detection (MySQL, MSSQL, ORA, PostgreSQL errors)
- Boolean-based blind (response length diff)
- Time-based blind (SLEEP/WAITFOR)
- Tests all GET params + form inputs

### XSS Module
- Reflected XSS (payload reflected unencoded)
- Partial reflection detection
- CSP presence check
- Tests GET params + form inputs

### LFI Module
- Path traversal variants (../../../etc/passwd, %2e%2e, etc.)
- Windows path testing
- Content indicator matching
- Identifies likely-vulnerable parameter names

### SSL/TLS Checker
- Certificate expiry & self-signed detection
- Weak protocol detection (SSLv2/v3, TLS 1.0/1.1)
- Weak cipher detection (RC4, DES, EXPORT, NULL)
- ASLR/DEP/cfg flag for PE
- Grade: A / B / C / F

### OSINT Recon
- DNS: A, AAAA, MX, NS, TXT records
- Passive subdomain enumeration (crt.sh / Certificate Transparency)
- Active subdomain bruteforce (DNS resolution)
- WHOIS parsing (registrar, dates, emails, nameservers)
- IP geolocation + ASN lookup
- Google dork generation (20+ templates)

### Binary Analyzer
- Magic byte file type detection (PE, ELF, Mach-O, APK, etc.)
- Shannon entropy calculation (detect encrypted/packed)
- String extraction (ASCII + UTF-16)
- Suspicious string classification (network, crypto, credentials, anti-debug)
- PE header parsing (arch, compile time, DLL flags, ASLR/DEP/CFG)
- ELF header parsing (arch, class, endianness)
- Risk scoring 0-100

---

## ⚖️ Legal

- Only test systems you own or have **explicit written permission** to test
- In Indonesia: UU ITE Pasal 30 prohibits unauthorized access
- Use on bug bounty platforms (HackerOne, Bugcrowd) with scope defined
- Use your own lab (DVWA, HackTheBox, TryHackMe)
