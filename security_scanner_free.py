# security_scanner_free.py
# 100% OFFLINE safe scanner. No network calls. No data leaves the server.

import re
import ast
import os

_PATTERNS = {
    "🔴 Data Theft": [
        r'os\.walk\s*\(\s*["\'][/\\](?:root|home|etc|var|proc)["\']',
        r'send_document\s*\(.*open\s*\(\s*["\'][/\\](?:root|etc|proc|sys)',
        r'glob\.glob\s*\(["\'][/\\]\*',
    ],
    "🔴 Backdoor": [
        r'marshal\.loads\s*\(',
        r'__import__\s*\(\s*["\']os["\']\s*\)\s*\.\s*system',
    ],
    "🟡 Obfuscation": [
        r'base64\.b64decode\s*\(.*\)\s*[\)\s]*\bexec\b',
        r'zlib\.decompress\s*\(.*\)\s*[\)\s]*\bexec\b',
        r'(?:\\x[0-9a-fA-F]{2}){10,}',
    ],
    "🟡 Suspicious Network": [
        r'requests\.(post|put)\s*\(\s*["\']https?://(?!api\.telegram\.org)',
        r'urllib\.request\.urlopen\s*\(\s*["\']https?://(?!api\.telegram\.org)',
        r'pastebin\.com/raw',
        r'devil-api\.com|elementfx\.io',
    ],
    "🟠 Resource Abuse": [
        r'multiprocessing\.Pool\s*\(\s*(?:None|\d{3,})',
        r'fork\s*\(\s*\).*fork\s*\(',
    ],
}

_TOKEN_RE = re.compile(r'\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b')


def _static_scan(code):
    results = {}
    for category, pats in _PATTERNS.items():
        hits = []
        for pat in pats:
            try:
                if re.search(pat, code, re.IGNORECASE | re.MULTILINE):
                    hits.append(pat[:60])
            except re.error:
                continue
        if hits:
            results[category] = hits
    tokens = _TOKEN_RE.findall(code)
    if tokens:
        results.setdefault("🔴 Exposed Credentials", [])
        results["🔴 Exposed Credentials"].append("Bot token hardcoded in code")
    return results


def _ast_scan(code):
    findings = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"Syntax error: {e}"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "walk":
                if isinstance(func.value, ast.Name) and func.value.id == "os":
                    if node.args and isinstance(node.args[0], ast.Constant):
                        if node.args[0].value in ["/root", "/etc", "/home", "/proc"]:
                            findings.append(f"os.walk('{node.args[0].value}') - sensitive scan")
            if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                if node.args and isinstance(node.args[0], ast.Call):
                    findings.append(f"Dangerous dynamic {func.id}()")
            if isinstance(func, ast.Name) and func.id == "__import__":
                if node.args and isinstance(node.args[0], ast.Constant):
                    if node.args[0].value == "os":
                        findings.append("Dynamic __import__('os')")
    return findings


def _risk_score(static_findings, ast_findings):
    weights = {
        "🔴 Data Theft": 40,
        "🔴 Backdoor": 40,
        "🔴 Exposed Credentials": 10,
        "🟡 Suspicious Network": 12,
        "🟡 Obfuscation": 10,
        "🟠 Resource Abuse": 8,
    }
    score = sum(weights.get(c, 5) * min(len(h), 3)
                for c, h in static_findings.items() if h)
    score += min(len(list(dict.fromkeys(ast_findings))) * 5, 20)
    return min(score, 100)


def _verdict(score, static_findings):
    has_blocking = any(static_findings.get(c) for c in ("🔴 Data Theft", "🔴 Backdoor"))
    if has_blocking and score >= 70:
        return "DANGEROUS", "REJECT"
    if score >= 85:
        return "DANGEROUS", "REJECT"
    if score >= 55:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    return "SAFE", "APPROVE"


def _scan_code(code, filename="file.py"):
    sf = _static_scan(code)
    af = _ast_scan(code)
    score = _risk_score(sf, af)
    verdict, rec = _verdict(score, sf)
    all_threats = [f"{c}: {h[0]}" for c, h in sf.items() for h in h[:1]] + af
    if verdict == "DANGEROUS":
        summary = f"⚠️ DANGEROUS: {len(all_threats)} threats detected"
    elif verdict == "SUSPICIOUS":
        summary = "🔍 Suspicious — needs manual review"
    else:
        summary = "✅ Safe — no major threats"
    return {
        "verdict": verdict,
        "risk_score": score,
        "findings": sf,
        "ast_findings": af,
        "all_threats": all_threats,
        "recommendation": rec,
        "summary": summary,
        "filename": filename,
    }


def scan_file(file_path):
    """Main entry — 100% offline, no network."""
    filename = os.path.basename(file_path)
    try:
        if filename.lower().endswith(('.py', '.js', '.ts', '.txt', '.json')):
            with open(file_path, 'r', errors='ignore') as f:
                return _scan_code(f.read(), filename)
        else:
            return {
                "verdict": "SUSPICIOUS",
                "risk_score": 20,
                "findings": {"🟡 Warning": [f"Unknown type: {filename}"]},
                "ast_findings": [],
                "recommendation": "MANUAL_REVIEW",
                "summary": f"File type '{filename}' not scanned.",
                "all_threats": [],
                "filename": filename,
            }
    except Exception as e:
        return {
            "verdict": "ERROR",
            "risk_score": 50,
            "findings": {},
            "ast_findings": [],
            "recommendation": "MANUAL_REVIEW",
            "summary": f"Scan error: {e}",
            "all_threats": [],
            "filename": filename,
              }
