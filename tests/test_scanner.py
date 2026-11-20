
import unittest

from scanner.security_scanner import scan_code


class TestSecurityScanner(unittest.TestCase):

    def test_hardcoded_password(self):
        code = 'password = "admin123"'

        findings = scan_code(code)

        self.assertTrue(
            any(f["issue"] == "Possible hard-coded secret"
                for f in findings)
        )

    def test_hardcoded_api_key(self):
        code = 'api_key = "my_secret_key"'

        findings = scan_code(code)

        self.assertTrue(
            any(f["issue"] == "Possible hard-coded secret"
                for f in findings)
        )

    def test_eval_detection(self):
        code = 'result = eval("2 + 3")'

        findings = scan_code(code)

        self.assertTrue(
            any(f["issue"] == "Use of eval()"
                for f in findings)
        )

    def test_unsafe_sql_detection(self):
        code = 'cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)'

        findings = scan_code(code)

        self.assertTrue(
            any(f["issue"] == "Possible unsafe SQL query"
                for f in findings)
        )

    def test_safe_code(self):
        code = 'print("Hello Rakshak")'

        findings = scan_code(code)

        self.assertEqual(findings, [])

    def test_line_number_detection(self):
        code = (
            'name = "Rakshak"\n'
            'print(name)\n'
            'result = eval("2 + 3")'
        )

        findings = scan_code(code)

        eval_findings = [
            f for f in findings
            if f["issue"] == "Use of eval()"
        ]

        self.assertEqual(eval_findings[0]["line"], 3)


if __name__ == "__main__":
    unittest.main()
