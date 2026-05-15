"""
core/nuclei_scan.py - Nuclei vulnerability scanner integration
Auto-downloads nuclei binary if not found.
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import tarfile
import json
import platform
import tempfile

NUCLEI_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools")
NUCLEI_RELEASES = "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"


def _nuclei_binary() -> str | None:
    """Return path to nuclei binary, or None if not found."""
    # Check PATH first
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, "nuclei" + (".exe" if sys.platform == "win32" else ""))
        if os.path.isfile(candidate):
            return candidate
    # Check tools/
    local = os.path.join(NUCLEI_DIR, "nuclei" + (".exe" if sys.platform == "win32" else ""))
    if os.path.isfile(local):
        return local
    return None


def _get_download_url() -> str | None:
    ctx = __import__("ssl").create_default_context()
    try:
        req = urllib.request.Request(NUCLEI_RELEASES, headers={"User-Agent": "SecuritasScan/1.0"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            data = json.loads(r.read())
    except Exception:
        return None

    system = platform.system().lower()
    arch = platform.machine().lower()
    arch = "amd64" if arch in ("x86_64", "amd64") else "arm64" if "arm" in arch else arch

    for asset in data.get("assets", []):
        name = asset["name"].lower()
        if system in name and arch in name and name.endswith(".zip"):
            return asset["browser_download_url"]
    return None


def download_nuclei() -> dict:
    """Download nuclei binary to tools/ directory."""
    os.makedirs(NUCLEI_DIR, exist_ok=True)
    url = _get_download_url()
    if not url:
        return {"success": False, "error": "Could not find download URL for your platform"}

    try:
        tmp = tempfile.mktemp(suffix=".zip")
        urllib.request.urlretrieve(url, tmp)
        with zipfile.ZipFile(tmp, "r") as z:
            for member in z.namelist():
                if "nuclei" in member.lower() and not member.endswith("/"):
                    z.extract(member, NUCLEI_DIR)
                    extracted = os.path.join(NUCLEI_DIR, member)
                    final = os.path.join(NUCLEI_DIR, "nuclei" + (".exe" if sys.platform == "win32" else ""))
                    os.rename(extracted, final)
                    if sys.platform != "win32":
                        os.chmod(final, 0o755)
                    break
        os.unlink(tmp)
        return {"success": True, "path": final}
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_nuclei(target: str, templates: list = None, severity: str = "medium,high,critical") -> dict:
    """
    Run nuclei against a target URL.
    templates: list of template tags e.g. ['cve', 'misconfig', 'exposure']
    severity: comma-separated e.g. 'low,medium,high,critical'
    """
    binary = _nuclei_binary()
    if not binary:
        dl = download_nuclei()
        if not dl["success"]:
            return {
                "target": target,
                "error": "Nuclei not installed. " + dl.get("error", ""),
                "install_hint": "Download from https://github.com/projectdiscovery/nuclei/releases and place nuclei.exe in the tools/ folder",
                "findings": [],
            }
        binary = dl["path"]

    cmd = [
        binary, "-u", target,
        "-severity", severity,
        "-json",
        "-silent",
        "-timeout", "10",
        "-rate-limit", "50",
        "-no-color",
    ]
    if templates:
        cmd += ["-tags", ",".join(templates)]
    else:
        cmd += ["-tags", "cve,misconfig,exposure,takeover,default-login"]

    findings = []
    errors = []

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "template_id": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", "").upper(),
                    "matched_at": finding.get("matched-at", ""),
                    "description": finding.get("info", {}).get("description", "")[:200],
                    "tags": finding.get("info", {}).get("tags", []),
                    "reference": (finding.get("info", {}).get("reference") or [""])[0],
                })
            except Exception:
                pass
        if proc.returncode not in (0, 1):
            errors.append(proc.stderr[:500] if proc.stderr else "Unknown error")
    except subprocess.TimeoutExpired:
        errors.append("Scan timed out after 5 minutes")
    except Exception as e:
        errors.append(str(e))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    return {
        "target": target,
        "findings": findings,
        "total": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "errors": errors,
    }
