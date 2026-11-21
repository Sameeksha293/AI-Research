from scanner.ai_fixer import fix_code_with_ai

code = """
password = "admin123"
result = eval("2+3")
print(result)
"""

corrected_code = fix_code_with_ai(code, [])

print("CORRECTED CODE:")
print(corrected_code)
