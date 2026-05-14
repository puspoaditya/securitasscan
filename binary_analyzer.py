"""
core/binary_analyzer.py - Static Binary & File Analysis
Techniques: String extraction, entropy analysis, header detection, metadata extraction
"""

import os
import re
import math
import struct
import hashlib
import subprocess
from collections import Counter


# Magic bytes for file type detection
MAGIC_BYTES = {
    b'\x7fELF':                        ('ELF',    'Linux Executable/Library'),
    b'MZ':                             ('PE',     'Windows PE Executable'),
    b'\xca\xfe\xba\xbe':              ('MACH-O', 'macOS Mach-O (multi-arch)'),
    b'\xce\xfa\xed\xfe':              ('MACH-O', 'macOS Mach-O (32-bit)'),
    b'\xcf\xfa\xed\xfe':              ('MACH-O', 'macOS Mach-O (64-bit)'),
    b'PK\x03\x04':                    ('ZIP',    'ZIP Archive (JAR/APK/DOCX)'),
    b'PK\x05\x06':                    ('ZIP',    'ZIP Archive (empty)'),
    b'\x89PNG':                        ('PNG',    'PNG Image'),
    b'%PDF':                           ('PDF',    'PDF Document'),
    b'\xff\xd8\xff':                   ('JPEG',   'JPEG Image'),
    b'GIF8':                           ('GIF',    'GIF Image'),
    b'\x1f\x8b':                       ('GZIP',   'GZIP Archive'),
    b'BZh':                            ('BZIP2',  'BZIP2 Archive'),
    b'\xfd7zXZ':                       ('XZ',     'XZ Archive'),
    b'Rar!':                           ('RAR',    'RAR Archive'),
    b'ITSF':                           ('CHM',    'Windows CHM Help File'),
    b'\x4d\x5a\x90\x00':             ('DOS',    'DOS/Windows Executable'),
    b'dex\n':                          ('DEX',    'Android Dalvik Executable'),
    b'#!/':                            ('SCRIPT', 'Shell Script'),
    b'#!python':                       ('SCRIPT', 'Python Script'),
    b'\x00asm':                        ('WASM',   'WebAssembly Binary'),
}

# Suspicious strings patterns
SUSPICIOUS_PATTERNS = {
    "Network":     [
        r'https?://[\w\./:-]+',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?',
        r'socket|connect|bind|listen|recv|send',
        r'wget|curl|powershell|cmd\.exe|/bin/sh',
    ],
    "Crypto":      [
        r'AES|DES|RSA|RC4|MD5|SHA\d+|base64',
        r'encrypt|decrypt|cipher|hash|key',
        r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64 strings
    ],
    "Filesystem":  [
        r'C:\\Windows\\|/etc/passwd|/etc/shadow',
        r'RegOpenKey|RegSetValue|CreateFile|WriteFile',
        r'\.exe|\.dll|\.so|\.bat|\.ps1|\.vbs',
    ],
    "Obfuscation": [
        r'eval\s*\(',
        r'exec\s*\(',
        r'fromCharCode|charCodeAt',
        r'unescape|decodeURIComponent',
        r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}',
    ],
    "Credentials": [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'PRIVATE KEY',
        r'BEGIN RSA',
    ],
    "Process":     [
        r'system\s*\(|popen|subprocess|ShellExecute',
        r'CreateProcess|WinExec|ShellCode',
        r'VirtualAlloc|WriteProcessMemory|CreateRemoteThread',
    ],
    "Anti-Analysis": [
        r'IsDebuggerPresent|CheckRemoteDebugger',
        r'anti.?debug|sandbox|vm.?detect',
        r'VBOX|VMWARE|qemu|VirtualBox',
        r'sleep\s*\(\s*\d{4,}',  # Long sleep (evasion)
    ],
}


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of byte data.
    High entropy (>7.0) indicates encryption or compression.
    """
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def detect_file_type(data: bytes) -> tuple:
    """Detect file type from magic bytes."""
    for magic, (fmt, desc) in MAGIC_BYTES.items():
        if data[:len(magic)] == magic:
            return fmt, desc

    # Check for text files
    try:
        sample = data[:512].decode('utf-8')
        if sample.startswith('#!'):
            return 'SCRIPT', 'Script file'
        return 'TEXT', 'Plain text file'
    except Exception:
        pass

    return 'UNKNOWN', 'Unknown binary format'


def compute_hashes(data: bytes) -> dict:
    """Compute MD5, SHA1, SHA256 hashes."""
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_strings(data: bytes, min_length: int = 6) -> list:
    """
    Extract printable ASCII and Unicode strings from binary.
    Similar to Unix `strings` command.
    """
    # ASCII strings
    ascii_pattern = re.compile(
        rb'[ -~]{' + str(min_length).encode() + rb',}',
    )
    ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_pattern.findall(data)]

    # Unicode (UTF-16 LE) strings
    unicode_pattern = re.compile(
        rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}',
    )
    unicode_strings = []
    for match in unicode_pattern.findall(data):
        try:
            s = match.decode('utf-16-le').strip()
            if len(s) >= min_length:
                unicode_strings.append(s)
        except Exception:
            pass

    all_strings = list(dict.fromkeys(ascii_strings + unicode_strings))
    return all_strings


def find_suspicious_strings(strings: list) -> dict:
    """Classify strings by suspicious pattern categories."""
    findings = {cat: [] for cat in SUSPICIOUS_PATTERNS}

    for s in strings:
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    if s not in findings[category]:
                        findings[category].append(s)
                    break

    # Remove empty categories
    return {k: v for k, v in findings.items() if v}


def extract_pe_info(data: bytes) -> dict:
    """Extract basic PE (Windows executable) header information."""
    info = {}
    try:
        # DOS header: e_lfanew at offset 0x3C
        if len(data) < 0x40:
            return info

        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return info

        # PE signature
        pe_sig = data[e_lfanew:e_lfanew+4]
        if pe_sig != b'PE\x00\x00':
            return info

        # COFF header
        machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
        num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
        timestamp = struct.unpack_from('<I', data, e_lfanew + 8)[0]
        characteristics = struct.unpack_from('<H', data, e_lfanew + 22)[0]

        machine_types = {
            0x014c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x0200: "IA64",
            0x01c0: "ARM",
            0xaa64: "ARM64",
        }

        import datetime
        info = {
            "architecture":  machine_types.get(machine, f"0x{machine:04x}"),
            "num_sections":  num_sections,
            "compile_time":  datetime.datetime.utcfromtimestamp(timestamp).isoformat() if timestamp else "N/A",
            "is_dll":        bool(characteristics & 0x2000),
            "is_executable": bool(characteristics & 0x0002),
            "is_stripped":   bool(characteristics & 0x0200),
        }

        # Optional header: subsystem
        opt_magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
        if opt_magic in (0x10b, 0x20b):  # PE32 or PE32+
            subsystem_offset = e_lfanew + 24 + (68 if opt_magic == 0x10b else 84)
            if subsystem_offset + 2 <= len(data):
                subsystem = struct.unpack_from('<H', data, subsystem_offset)[0]
                subsystems = {
                    1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)",
                    9: "Windows CE GUI", 14: "Xbox", 16: "Windows Boot Application",
                }
                info["subsystem"] = subsystems.get(subsystem, f"0x{subsystem:04x}")

    except Exception:
        pass

    return info


def extract_elf_info(data: bytes) -> dict:
    """Extract basic ELF (Linux binary) header information."""
    info = {}
    try:
        if data[:4] != b'\x7fELF' or len(data) < 64:
            return info

        ei_class  = data[4]   # 1=32bit, 2=64bit
        ei_data   = data[5]   # 1=LE, 2=BE
        e_type    = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 16)[0]
        e_machine = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 18)[0]

        types = {1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core Dump"}
        machines = {
            0x03: "x86", 0x3e: "x86-64", 0x28: "ARM",
            0xb7: "AArch64", 0x08: "MIPS", 0x16: "PowerPC",
        }

        info = {
            "class":        "64-bit" if ei_class == 2 else "32-bit",
            "endianness":   "Little Endian" if ei_data == 1 else "Big Endian",
            "type":         types.get(e_type, f"0x{e_type:04x}"),
            "architecture": machines.get(e_machine, f"0x{e_machine:04x}"),
        }
    except Exception:
        pass

    return info


def check_security_features(data: bytes, file_type: str) -> dict:
    """Check for binary security mitigations."""
    features = {}

    if file_type == "ELF":
        # Check for stack canary (presence of __stack_chk_fail)
        features["stack_canary"]  = b'__stack_chk_fail' in data
        features["nx_bit"]        = b'GNU_STACK' in data  # Simplified check
        features["pie"]           = b'DW_CFA' in data  # Very rough
        features["relro"]         = b'GNU_RELRO' in data
        features["stripped"]      = b'.symtab' not in data

    elif file_type == "PE":
        # Check ASLR/NX from PE characteristics
        try:
            e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
            dll_char_offset = e_lfanew + 24 + 70  # DllCharacteristics in optional header
            if dll_char_offset + 2 <= len(data):
                dll_char = struct.unpack_from('<H', data, dll_char_offset)[0]
                features["aslr"]            = bool(dll_char & 0x0040)
                features["dep_nx"]          = bool(dll_char & 0x0100)
                features["seh"]             = bool(dll_char & 0x0400)
                features["cfg"]             = bool(dll_char & 0x4000)
                features["guard_cf"]        = bool(dll_char & 0x4000)
        except Exception:
            pass

    return features


def analyze_file(filepath: str) -> dict:
    """
    Main file analysis function.
    Returns comprehensive static analysis report.
    """
    if not os.path.isfile(filepath):
        return {"error": f"File not found: {filepath}"}

    with open(filepath, 'rb') as f:
        data = f.read()

    file_type, file_desc = detect_file_type(data)
    hashes = compute_hashes(data)
    entropy = calculate_entropy(data)
    all_strings = extract_strings(data)
    suspicious = find_suspicious_strings(all_strings)

    result = {
        "filepath":        filepath,
        "filename":        os.path.basename(filepath),
        "size_bytes":      len(data),
        "file_type":       file_type,
        "file_desc":       file_desc,
        "hashes":          hashes,
        "entropy":         entropy,
        "entropy_risk":    _entropy_risk(entropy),
        "total_strings":   len(all_strings),
        "suspicious":      suspicious,
        "security_features": {},
        "pe_info":         {},
        "elf_info":        {},
        "risk_score":      0,
        "risk_indicators": [],
    }

    # Type-specific analysis
    if file_type == "PE":
        result["pe_info"] = extract_pe_info(data)
        result["security_features"] = check_security_features(data, "PE")
    elif file_type == "ELF":
        result["elf_info"] = extract_elf_info(data)
        result["security_features"] = check_security_features(data, "ELF")

    # Risk scoring
    result["risk_score"], result["risk_indicators"] = _calculate_risk(result)

    return result


def _entropy_risk(entropy: float) -> str:
    if entropy > 7.5:
        return "HIGH - Likely encrypted/packed"
    elif entropy > 7.0:
        return "MEDIUM - Possibly compressed"
    elif entropy > 6.0:
        return "LOW - Some compression"
    else:
        return "NORMAL"


def _calculate_risk(analysis: dict) -> tuple:
    score = 0
    indicators = []

    # Entropy
    if analysis["entropy"] > 7.5:
        score += 25
        indicators.append("High entropy: likely encrypted/obfuscated")

    # Suspicious strings
    suspicious = analysis.get("suspicious", {})
    if "Process" in suspicious:
        score += 20
        indicators.append(f"Process manipulation strings found: {len(suspicious['Process'])} items")
    if "Anti-Analysis" in suspicious:
        score += 20
        indicators.append("Anti-debugging/anti-VM techniques detected")
    if "Credentials" in suspicious:
        score += 15
        indicators.append("Hardcoded credentials or keys found")
    if "Network" in suspicious:
        score += 10
        indicators.append(f"Network activity strings: {len(suspicious['Network'])} items")
    if "Obfuscation" in suspicious:
        score += 15
        indicators.append("Code obfuscation patterns detected")

    # Security features (missing = risk)
    sec = analysis.get("security_features", {})
    if sec.get("aslr") is False:
        score += 5
        indicators.append("ASLR disabled")
    if sec.get("dep_nx") is False:
        score += 5
        indicators.append("DEP/NX disabled")
    if sec.get("stack_canary") is False and analysis["file_type"] == "ELF":
        score += 5
        indicators.append("No stack canary detected")

    return min(score, 100), indicators


def print_analysis(result: dict):
    """Pretty print binary analysis to terminal."""
    c = Colors
    print(f"\n{c.CYAN}{c.BOLD}{'═'*60}{c.RESET}")
    print(f"{c.BOLD}  FILE    : {c.GREEN}{result['filename']}{c.RESET}")
    print(f"{c.BOLD}  TYPE    : {c.YELLOW}{result['file_type']} — {result['file_desc']}{c.RESET}")
    print(f"{c.BOLD}  SIZE    : {result['size_bytes']:,} bytes{c.RESET}")
    print(f"{c.BOLD}  ENTROPY : {result['entropy']} ({result['entropy_risk']}){c.RESET}")
    print(f"{c.BOLD}  RISK    : {c.RED if result['risk_score'] > 50 else c.YELLOW}{result['risk_score']}/100{c.RESET}")
    print(f"\n{c.BOLD}  Hashes:{c.RESET}")
    for algo, val in result["hashes"].items():
        print(f"    {algo.upper()}: {val}")
    if result["risk_indicators"]:
        print(f"\n{c.BOLD}  Risk Indicators:{c.RESET}")
        for ind in result["risk_indicators"]:
            print(f"    {c.RED}⚠{c.RESET}  {ind}")
    if result["suspicious"]:
        print(f"\n{c.BOLD}  Suspicious Strings:{c.RESET}")
        for cat, strings in result["suspicious"].items():
            print(f"    [{c.YELLOW}{cat}{c.RESET}]")
            for s in strings[:5]:
                print(f"      → {s[:80]}")
