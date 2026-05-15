"""
api/server.py - Flask REST API
Exposes all scanner modules as JSON endpoints for the Web UI
"""

import sys
import os
import json
import threading
import time
import uuid
from collections import defaultdict
from functools import wraps

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

try:
    from flask import Flask, request, jsonify, Response
    from flask_cors import CORS
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[!] Flask not installed. Run: pip install flask flask-cors")

from core.db import init_db, save_scan, update_scan, get_history
from core.scanner import scan_ports, TOP_PORTS
from core.web_scanner import full_web_scan
from core.recon import full_recon
from core.binary_analyzer import analyze_file
from modules.vuln_testers import test_xss_parameter, scan_url_for_xss, scan_url_for_lfi, check_ssl
from modules.sqli import scan_url_params, scan_forms
from config import API_HOST, API_PORT

# In-memory job store
jobs = {}

# Rate limiting store: {ip: [timestamp, ...]}
_rate_store = defaultdict(list)
_rate_lock = threading.Lock()
RATE_LIMIT = 20       # max requests
RATE_WINDOW = 60      # per N seconds

# Optional API key (set env var SCAN_API_KEY to enable)
API_KEY = os.environ.get("SCAN_API_KEY", "")


def create_app():
    if not HAS_FLASK:
        return None

    # Serve web/index.html at root
    web_dir = os.path.join(os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "web")
    app = Flask(__name__, static_folder=web_dir, static_url_path="")
    CORS(app)
    init_db()

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    # ─────────────────────────
    # Rate limiting + auth
    # ─────────────────────────

    def rate_limited(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # API key check
            if API_KEY:
                key = request.headers.get("X-API-Key") or request.args.get("api_key")
                if key != API_KEY:
                    return jsonify({"error": "Invalid or missing API key"}), 401
            # Rate limit by IP
            ip = request.remote_addr or "unknown"
            now = time.time()
            with _rate_lock:
                _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
                if len(_rate_store[ip]) >= RATE_LIMIT:
                    return jsonify({"error": f"Rate limit exceeded: {RATE_LIMIT} requests per {RATE_WINDOW}s"}), 429
                _rate_store[ip].append(now)
            return f(*args, **kwargs)
        return decorated

    # ─────────────────────────
    # Job management
    # ─────────────────────────

    def run_job(job_id: str, func, *args, **kwargs):
        jobs[job_id]["status"] = "running"
        jobs[job_id]["started_at"] = time.time()
        try:
            result = func(*args, **kwargs)
            jobs[job_id]["result"] = result
            jobs[job_id]["status"] = "done"
            update_scan(job_id, "done", result=result)
        except Exception as e:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = str(e)
            update_scan(job_id, "error", error=str(e))
        jobs[job_id]["finished_at"] = time.time()

    def create_job(func, *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())[:8]
        jobs[job_id] = {"status": "queued", "result": None, "error": None, "progress": None}
        t = threading.Thread(target=run_job, args=(job_id, func, *args), kwargs=kwargs, daemon=True)
        t.start()
        return job_id

    def create_tracked_job(func, scan_type: str, target: str, *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())[:8]
        jobs[job_id] = {"status": "queued", "result": None, "error": None, "progress": None}
        save_scan(job_id, scan_type, target)
        t = threading.Thread(target=run_job, args=(job_id, func, *args), kwargs=kwargs, daemon=True)
        t.start()
        return job_id

    def create_job_with_progress(func, *args, **kwargs) -> str:
        job_id = str(uuid.uuid4())[:8]
        jobs[job_id] = {"status": "queued", "result": None, "error": None, "progress": None}
        def progress_cb(current, total):
            jobs[job_id]["progress"] = {"current": current, "total": total}
        kwargs["callback"] = progress_cb
        t = threading.Thread(target=run_job, args=(job_id, func, *args), kwargs=kwargs, daemon=True)
        t.start()
        return job_id

    # ─────────────────────────
    # API Routes
    # ─────────────────────────

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "version": "1.0.0"})

    @app.route("/api/history", methods=["GET"])
    def api_history():
        limit = int(request.args.get("limit", 50))
        return jsonify(get_history(limit))

    @app.route("/api/jobs/<job_id>", methods=["GET"])
    def get_job(job_id):
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job)

    @app.route("/api/jobs", methods=["GET"])
    def list_jobs():
        return jsonify([
            {"id": k, "status": v["status"]}
            for k, v in jobs.items()
        ])

    # Port Scanner
    @app.route("/api/scan/ports", methods=["POST"])
    @rate_limited
    def api_port_scan():
        data = request.json or {}
        target = data.get("target", "")
        if not target:
            return jsonify({"error": "target required"}), 400

        scan_type = data.get("scan_type", "top")
        custom_ports = data.get("ports", [])
        threads = data.get("threads", 50)
        grab_banners = data.get("grab_banners", True)

        if scan_type == "top":
            ports = TOP_PORTS
        elif scan_type == "custom" and custom_ports:
            ports = custom_ports
        elif scan_type == "full":
            ports = list(range(1, 65536))
        else:
            ports = TOP_PORTS

        job_id = create_job_with_progress(
            scan_ports,
            target=target,
            ports=ports,
            threads=threads,
            grab_banners=grab_banners,
        )
        save_scan(job_id, "PORT_SCAN", target)
        return jsonify({"job_id": job_id, "message": "Port scan started"})

    # Web Scanner
    @app.route("/api/scan/web", methods=["POST"])
    @rate_limited
    def api_web_scan():
        data = request.json or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "url required"}), 400
        if not url.startswith("http"):
            url = "http://" + url

        fuzz = data.get("fuzz_dirs", True)
        job_id = create_job(full_web_scan, url=url, fuzz_dirs=fuzz)
        save_scan(job_id, "WEB_SCAN", url)
        return jsonify({"job_id": job_id, "message": "Web scan started"})

    # SQLi Scanner
    @app.route("/api/scan/sqli", methods=["POST"])
    @rate_limited
    def api_sqli():
        data = request.json or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "url required"}), 400

        def run_sqli():
            from core.web_scanner import full_web_scan, extract_forms
            from core.web_scanner import make_request
            resp = make_request(url)
            forms = extract_forms(resp["body"], url) if resp else []
            param_results = scan_url_params(url)
            form_results = scan_forms(url, forms)
            return {
                "url": url,
                "param_results": param_results,
                "form_results": form_results,
                "total_vulnerabilities": len(param_results) + len(form_results),
            }

        job_id = create_job(run_sqli)
        save_scan(job_id, "SQLI", url)
        return jsonify({"job_id": job_id, "message": "SQLi scan started"})

    # XSS Scanner
    @app.route("/api/scan/xss", methods=["POST"])
    @rate_limited
    def api_xss():
        data = request.json or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "url required"}), 400

        def run_xss():
            from core.web_scanner import make_request, extract_forms
            resp = make_request(url)
            forms = extract_forms(resp["body"], url) if resp else []
            param_results = scan_url_for_xss(url)
            from modules.vuln_testers import scan_forms_for_xss
            form_results = scan_forms_for_xss(url, forms)
            return {
                "url": url,
                "param_results": param_results,
                "form_results": form_results,
                "total_vulnerabilities": len(param_results) + len(form_results),
            }

        job_id = create_job(run_xss)
        save_scan(job_id, "XSS", url)
        return jsonify({"job_id": job_id, "message": "XSS scan started"})

    # LFI Scanner
    @app.route("/api/scan/lfi", methods=["POST"])
    @rate_limited
    def api_lfi():
        data = request.json or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "url required"}), 400

        job_id = create_job(scan_url_for_lfi, url=url)
        save_scan(job_id, "LFI", url)
        return jsonify({"job_id": job_id, "message": "LFI scan started"})

    # SSL Checker
    @app.route("/api/scan/ssl", methods=["POST"])
    @rate_limited
    def api_ssl():
        data = request.json or {}
        hostname = data.get("hostname", "").replace("https://", "").replace("http://", "").split("/")[0]
        port = data.get("port", 443)
        if not hostname:
            return jsonify({"error": "hostname required"}), 400

        job_id = create_job(check_ssl, hostname=hostname, port=port)
        save_scan(job_id, "SSL", hostname)
        return jsonify({"job_id": job_id, "message": "SSL check started"})

    # Recon / OSINT
    @app.route("/api/scan/recon", methods=["POST"])
    @rate_limited
    def api_recon():
        data = request.json or {}
        domain = data.get("domain", "")
        if not domain:
            return jsonify({"error": "domain required"}), 400

        brute = data.get("brute_subdomains", True)
        job_id = create_job(full_recon, domain=domain, brute_subdomains=brute)
        save_scan(job_id, "RECON", domain)
        return jsonify({"job_id": job_id, "message": "Recon started"})

    # Binary Analysis
    @app.route("/api/scan/binary", methods=["POST"])
    @rate_limited
    def api_binary():
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        f = request.files["file"]
        tmp_path = f"/tmp/{uuid.uuid4().hex}_{f.filename}"
        f.save(tmp_path)
        job_id = create_job(analyze_file, filepath=tmp_path)
        return jsonify({"job_id": job_id, "message": "Binary analysis started"})

    # Full combined scan
    @app.route("/api/scan/full", methods=["POST"])
    @rate_limited
    def api_full_scan():
        data = request.json or {}
        target = data.get("target", "")
        if not target:
            return jsonify({"error": "target required"}), 400

        url = target if target.startswith("http") else f"http://{target}"
        domain = url.replace("http://", "").replace("https://", "").split("/")[0]

        def run_full():
            import concurrent.futures as cf
            results = {}
            with cf.ThreadPoolExecutor(max_workers=3) as ex:
                port_f = ex.submit(scan_ports, target=domain, ports=TOP_PORTS)
                web_f  = ex.submit(full_web_scan, url=url, fuzz_dirs=True)
                recon_f = ex.submit(full_recon, domain=domain, brute_subdomains=False)

                results["ports"] = port_f.result()
                results["web"]   = web_f.result()
                results["recon"] = recon_f.result()

            # Run vuln checks if web scan succeeded
            if results["web"]["reachable"]:
                results["sqli"]  = scan_url_params(url)
                results["xss"]   = scan_url_for_xss(url)
                results["lfi"]   = scan_url_for_lfi(url)
                results["ssl"]   = check_ssl(domain)

            return results

        job_id = create_job(run_full)
        save_scan(job_id, "FULL_SCAN", target)
        return jsonify({"job_id": job_id, "message": "Full scan started"})

    # Subdomain Takeover
    @app.route("/api/scan/takeover", methods=["POST"])
    @rate_limited
    def api_takeover():
        from core.subdomain_takeover import scan_subdomain_takeover
        data = request.json or {}
        subdomains = data.get("subdomains", [])
        if not subdomains:
            return jsonify({"error": "subdomains list required"}), 400
        job_id = create_job(scan_subdomain_takeover, subdomains=subdomains)
        save_scan(job_id, "TAKEOVER", f"{len(subdomains)} subdomains")
        return jsonify({"job_id": job_id, "message": "Takeover check started"})

    # CVE Lookup
    @app.route("/api/scan/cve", methods=["POST"])
    @rate_limited
    def api_cve():
        from core.cve_lookup import lookup_cves, lookup_cves_for_server
        data = request.json or {}
        technologies = data.get("technologies", [])
        server_header = data.get("server_header", "")
        if not technologies and not server_header:
            return jsonify({"error": "technologies or server_header required"}), 400

        def run_cve():
            result = {}
            if technologies:
                result["by_technology"] = lookup_cves(technologies)
            if server_header:
                result["by_server"] = lookup_cves_for_server(server_header)
            return result

        job_id = create_job(run_cve)
        return jsonify({"job_id": job_id, "message": "CVE lookup started"})

    return app


if __name__ == "__main__":
    app = create_app()
    if app:
        print(f"[*] Starting SecuritasScan API on http://{API_HOST}:{API_PORT}")
        app.run(host=API_HOST, port=API_PORT, debug=False, threaded=True)
