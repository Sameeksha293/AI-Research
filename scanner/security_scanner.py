
import hashlib
import re
from collections import Counter


def generate_code_fingerprint(code):
    """Generate SHA-256 fingerprint of submitted code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def scan_code(code):
    findings = []

    checks = [
        {
            "name": "Possible hard-coded secret",
            "pattern": r"""(?i)\b(api_key|password|secret)\s*=\s*["'][^"']+["']""",
            "severity": "HIGH",
            "description": "A password, API key, or secret may be stored directly in source code.",
            "recommendation": "Move secrets into environment variables."
        },
        {
            "name": "Possible SQL Injection",
            "pattern": r"""(?is)(?:execute|executemany)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:\+|%))""",
            "severity": "HIGH",
            "description": "SQL query may include dynamically joined or formatted user input.",
            "recommendation": "Use parameterized SQL queries with placeholders."
        },
        {
            "name": "Possible SQL Injection through query variable",
            "pattern": r"""(?is)\b\w+\s*=\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+\s*\w+""",
            "severity": "HIGH",
            "description": "SQL query appears to be constructed using string concatenation.",
            "recommendation": "Use parameterized SQL queries instead of concatenation."
        },
        {
            "name": "Use of eval()",
            "pattern": r"\beval\s*\(",
            "severity": "HIGH",
            "description": "eval() executes dynamic expressions and may allow arbitrary code execution.",
            "recommendation": "Avoid eval(). Use safer alternatives such as ast.literal_eval() when appropriate."
        },
        {
            "name": "Possible unsafe system command",
            "pattern": r"""(?i)\bos\.system\s*\(""",
            "severity": "HIGH",
            "description": "os.system() may execute unsafe operating system commands.",
            "recommendation": "Use subprocess with a fixed executable and argument list."
        }
    ]

    for check in checks:
        for match in re.finditer(check["pattern"], code):
            line = code.count("\n", 0, match.start()) + 1

            findings.append({
                "issue": check["name"],
                "severity": check["severity"],
                "line": line,
                "description": check["description"],
                "recommendation": check["recommendation"]
            })

    return findings


def compare_code_versions(old_code, new_code):
    old_findings = scan_code(old_code)
    new_findings = scan_code(new_code)

    old_counts = Counter(f["issue"] for f in old_findings)
    new_counts = Counter(f["issue"] for f in new_findings)

    fixed = []
    remaining = []
    introduced = []

    all_issues = set(old_counts) | set(new_counts)

    for issue in all_issues:
        old_count = old_counts[issue]
        new_count = new_counts[issue]

        if old_count > new_count:
            fixed.extend([issue] * (old_count - new_count))

        elif new_count > old_count:
            introduced.extend([issue] * (new_count - old_count))

        remaining.extend([issue] * min(old_count, new_count))

    return {
        "old_fingerprint": generate_code_fingerprint(old_code),
        "new_fingerprint": generate_code_fingerprint(new_code),
        "fingerprints_changed": old_code != new_code,
        "fixed": fixed,
        "remaining": remaining,
        "introduced": introduced
    }
