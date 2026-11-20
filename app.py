
from flask import Flask, render_template, request
from scanner.security_scanner import scan_code

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    findings = []
    submitted_code = ""
    scanned = False

    if request.method == "POST":
        submitted_code = request.form.get("code", "")
        scanned = True

        if submitted_code.strip():
            findings = scan_code(submitted_code)

    return render_template(
        "index.html",
        findings=findings,
        submitted_code=submitted_code,
        scanned=scanned
    )


if __name__ == "__main__":
    app.run(debug=True)
