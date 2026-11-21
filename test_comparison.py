
import json

from scanner.security_scanner import compare_code_versions


# Original code (before fixing security issues)
old_code = '''
password = "admin123"
result = eval("2+3")
'''


# Updated code (after fixing security issues)
new_code = '''
import os

password = os.getenv("PASSWORD")
print("Hello")
'''


# Compare both code versions
result = compare_code_versions(old_code, new_code)


# Display comparison results
print(json.dumps(result, indent=2))
