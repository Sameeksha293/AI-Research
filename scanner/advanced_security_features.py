
import ast
import os
from pathlib import Path


# ==========================================
# 1. WHAT-IF SECURITY SIMULATOR
# ==========================================

def run_what_if_simulator(findings, impact_map=None):

    findings = findings or []
    impact_map = impact_map or {}

    scenarios = []

    for finding in findings:

        issue = str(
            finding.get("issue", finding.get("name", "Security issue"))
        )

        issue_lower = issue.lower()

        if "secret" in issue_lower or "password" in issue_lower:
            consequence = (
                "An exposed credential could be discovered and misused."
            )
            solution = (
                "Move credentials into environment variables or a secret manager."
            )

        elif "sql" in issue_lower:
            consequence = (
                "An attacker may manipulate database queries "
                "if untrusted input reaches the query."
            )
            solution = (
                "Use parameterized SQL queries."
            )

        elif "eval" in issue_lower:
            consequence = (
                "Untrusted expressions passed to eval() may execute "
                "unexpected Python code."
            )
            solution = (
                "Avoid eval() and use safe parsing or explicit input validation."
            )

        else:
            consequence = (
                "This pattern may introduce a security weakness."
            )
            solution = (
                "Review the finding and apply an appropriate secure coding practice."
            )

        scenarios.append({
            "issue": issue,
            "line": finding.get("line", "Unknown"),
            "what_if": consequence,
            "recommended_action": solution,
            "status": "Potential risk"
        })

    paths = impact_map.get("paths", [])

    return {
        "total_scenarios": len(scenarios),
        "scenarios": scenarios,
        "potential_risk_paths": len(paths),
        "disclaimer": (
            "These are educational simulations, not actual attacks "
            "or predictions of real-world exploitation."
        )
    }


# ==========================================
# 2. AI FIX CONFIDENCE LAB
# ==========================================

def evaluate_fix_confidence(original_code, corrected_code, scan_function):

    if not corrected_code or not corrected_code.strip():

        return {
            "confidence": 0,
            "status": "No correction available",
            "checks": [],
            "message": "No corrected code was provided."
        }

    checks = []

    # Check Python syntax
    try:
        ast.parse(corrected_code)
        syntax_passed = True
        checks.append({
            "name": "Python Syntax",
            "status": "Passed"
        })

    except SyntaxError:
        syntax_passed = False
        checks.append({
            "name": "Python Syntax",
            "status": "Failed"
        })

    # Scan original and corrected code
    try:
        original_findings = scan_function(original_code)
        corrected_findings = scan_function(corrected_code)

        original_count = len(original_findings)
        corrected_count = len(corrected_findings)

        checks.append({
            "name": "Original Security Findings",
            "count": original_count
        })

        checks.append({
            "name": "Remaining Security Findings",
            "count": corrected_count
        })

        if corrected_count < original_count:
            checks.append({
                "name": "Finding Comparison",
                "status": "Improved"
            })
        elif corrected_count == original_count:
            checks.append({
                "name": "Finding Comparison",
                "status": "No change"
            })
        else:
            checks.append({
                "name": "Finding Comparison",
                "status": "More findings detected"
            })

    except Exception as error:
        return {
            "confidence": 0,
            "status": "Evaluation failed",
            "checks": checks,
            "message": str(error)
        }

    # Evidence-based heuristic score
    score = 0

    if syntax_passed:
        score += 40

    if corrected_count < original_count:
        score += 40
    elif corrected_count == original_count:
        score += 10

    if corrected_code != original_code:
        score += 20

    if score >= 80:
        status = "Promising"
    elif score >= 40:
        status = "Needs review"
    else:
        status = "Low confidence"

    return {
        "confidence": score,
        "status": status,
        "checks": checks,
        "original_findings": original_count,
        "remaining_findings": corrected_count,
        "message": (
            "This score reflects basic syntax and scanner checks. "
            "It is not proof that the correction is secure."
        )
    }


# ==========================================
# 3. MISSING CONFIGURATION CHECKER
# ==========================================

def check_missing_configuration(project_directory):

    project_path = Path(project_directory)

    checks = []

    if not project_path.exists() or not project_path.is_dir():
        return {
            "success": False,
            "checks": [],
            "message": "Project directory does not exist."
        }

    env_file = project_path / ".env"
    env_example = project_path / ".env.example"
    requirements_file = project_path / "requirements.txt"

    checks.append({
        "name": ".env file",
        "status": "Present" if env_file.is_file() else "Missing",
        "recommendation": (
            "Keep secrets in environment variables."
            if not env_file.is_file()
            else "Ensure this file is excluded from Git."
        )
    })

    checks.append({
        "name": ".env.example",
        "status": "Present" if env_example.is_file() else "Missing",
        "recommendation": "Provide a template of required environment variables without real secrets."
    })

    checks.append({
        "name": "requirements.txt",
        "status": "Present" if requirements_file.is_file() else "Missing",
        "recommendation": "Record project dependencies for reproducible installation."
    })

    gitignore = project_path / ".gitignore"

    if gitignore.is_file():
        try:
            gitignore_content = gitignore.read_text(
                encoding="utf-8",
                errors="replace"
            )

            ignores_env = any(
                line.strip() == ".env"
                for line in gitignore_content.splitlines()
            )

        except OSError:
            ignores_env = False
    else:
        ignores_env = False

    checks.append({
        "name": ".env Git protection",
        "status": "Passed" if ignores_env else "Warning",
        "recommendation": (
            "Verify .env is ignored by Git."
            if ignores_env
            else "Add .env to .gitignore to reduce accidental secret commits."
        )
    })

    app_file = project_path / "app.py"

    if app_file.is_file():

        try:
            app_code = app_file.read_text(
                encoding="utf-8",
                errors="replace"
            )

            debug_enabled = (
                "debug=True" in app_code
                or "DEBUG = True" in app_code
            )

            checks.append({
                "name": "Flask debug mode",
                "status": "Warning" if debug_enabled else "Not detected",
                "recommendation": (
                    "Disable debug mode before production deployment."
                    if debug_enabled
                    else "Review production configuration manually."
                )
            })

        except OSError:
            checks.append({
                "name": "Flask debug mode",
                "status": "Not checked",
                "recommendation": "Check Flask production settings."
            })

    missing_count = sum(
        1 for check in checks
        if check["status"] in ("Missing", "Warning")
    )

    return {
        "success": True,
        "total_checks": len(checks),
        "potential_missing_items": missing_count,
        "checks": checks,
        "disclaimer": (
            "This checker inspects selected project files and patterns. "
            "It does not verify every deployment or security setting."
        )
    }
