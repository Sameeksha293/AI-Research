import re

def scan_code(code):
    findings = []

    checks = [
        {
            "name": "Possible hard-coded secret",
            "pattern": r'(?i)(api_key|password|secret)\s*=\s*["\'][^"\']+["\']',
            "severity": "HIGH"
        },
        {
            "name": "Possible unsafe SQL query",
            "pattern": r'(?i)(execute|cursor\.execute)\s*\([^)]*%s',
            "severity": "MEDIUM"
        },
        {
            "name": "Use of eval()",
            "pattern": r'\beval\s*\(',
            "severity": "HIGH"
        }
    ]

    for check in checks:
        for match in re.finditer(check["pattern"], code):
            line = code.count("\n", 0, match.start()) + 1

            findings.append({
                "issue": check["name"],
                "severity": check["severity"],
                "line": line
            })

    return findings