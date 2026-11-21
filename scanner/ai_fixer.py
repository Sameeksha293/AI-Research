
import re
import os


def fix_code_with_ai(code, findings=None):
    """
    Rule-based Python security correction engine.
    Supports common SQL Injection patterns and hardcoded secrets.
    """

    if not isinstance(code, str) or not code.strip():
        raise ValueError("Please provide Python code to fix.")

    corrected_code = code
    changes = []

    # FIX 1: SQL Injection through string concatenation
    # Example:
    # query = "SELECT * FROM users WHERE id = " + user_id

    sql_pattern = re.compile(
        r"""(?m)^(\s*)(\w+)\s*=\s*(["'])(.*?)\3\s*\+\s*(\w+)\s*(?:\+\s*(["'])(.*?)\6)?\s*$"""
    )

    def fix_sql(match):
        indent = match.group(1)
        query_variable = match.group(2)
        prefix = match.group(4)
        input_variable = match.group(5)
        suffix = match.group(7) or ""

        if not re.search(
            r"\b(SELECT|INSERT|UPDATE|DELETE)\b",
            prefix,
            re.IGNORECASE
        ):
            return match.group(0)

        # Remove quotes surrounding the inserted user input.
        prefix = re.sub(r"""['"]$""", "", prefix)
        suffix = re.sub(r"""^['"]""", "", suffix)

        new_query = prefix + "?" + suffix

        changes.append(
            "Replaced unsafe SQL string concatenation with a parameterized query."
        )

        return (
            f'{indent}{query_variable} = {new_query!r}\n'
            f'{indent}cursor.execute({query_variable}, ({input_variable},))'
        )

    corrected_code = sql_pattern.sub(fix_sql, corrected_code)

    # FIX 2: Hardcoded passwords

    password_pattern = re.compile(
        r"""(?m)^(\s*)password\s*=\s*(['"])(.*?)\2\s*$"""
    )

    def replace_password(match):
        changes.append("Replaced hardcoded password with environment variable.")
        return (
            f'{match.group(1)}password = os.getenv("PASSWORD")'
        )

    corrected_code = password_pattern.sub(
        replace_password,
        corrected_code
    )

    # FIX 3: Hardcoded API keys and secrets

    api_pattern = re.compile(
        r"""(?m)^(\s*)(api_key|secret_key)\s*=\s*(['"])(.*?)\3\s*$"""
    )

    def replace_api_key(match):
        variable = match.group(2)

        changes.append(
            f"Replaced hardcoded {variable} with environment variable."
        )

        return (
            f'{match.group(1)}{variable} = '
            f'os.getenv("{variable.upper()}")'
        )

    corrected_code = api_pattern.sub(
        replace_api_key,
        corrected_code
    )

    # FIX 4: Add os import when required

    if "os.getenv(" in corrected_code:
        if not re.search(r"(?m)^\s*import\s+os\b", corrected_code):
            corrected_code = "import os\n" + corrected_code

    # FIX 5: Check corrected Python syntax

    try:
        compile(corrected_code, "<corrected_code>", "exec")
    except SyntaxError as error:
        raise ValueError(
            f"Correction produced invalid Python syntax: {error}"
        )

    if not changes:
        changes.append(
            "No supported automatic correction was found. "
            "Manual review is recommended."
        )

    return corrected_code
