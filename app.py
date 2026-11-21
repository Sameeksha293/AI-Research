
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request

from scanner.security_scanner import (
    scan_code,
    generate_code_fingerprint,
    compare_code_versions,
)

from scanner.ai_fixer import fix_code_with_ai

from scanner.security_impact_map import (
    generate_security_impact_map,
)

from scanner.security_nutrition_label import (
    generate_security_nutrition_label,
)

from scanner.advanced_security_features import (
    run_what_if_simulator,
    evaluate_fix_confidence,
    check_missing_configuration,
)


# ENVIRONMENT
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env", override=False)


# FLASK APP
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def home():

    findings = []
    submitted_code = ""
    fingerprint = ""
    scanned = False

    comparison = None
    old_code = ""
    new_code = ""

    corrected_code = ""
    fix_error = None
    fix_requested = False

    impact_map = None
    nutrition_label = None
    what_if_result = None
    fix_confidence = None

    # Check project configuration
    configuration_report = check_missing_configuration(BASE_DIR)

    if request.method == "POST":

        action = request.form.get("action", "scan")

        # SCAN CODE
        if action == "scan":

            submitted_code = request.form.get("code", "")
            scanned = True

            if submitted_code.strip():

                fingerprint = generate_code_fingerprint(submitted_code)
                findings = scan_code(submitted_code)

                impact_map = generate_security_impact_map(
                    submitted_code
                )

                nutrition_label = generate_security_nutrition_label(
                    submitted_code,
                    findings,
                    impact_map
                )

                what_if_result = run_what_if_simulator(
                    findings,
                    impact_map
                )

        # COMPARE CODE
        elif action == "compare":

            old_code = request.form.get("old_code", "")
            new_code = request.form.get("new_code", "")

            if old_code.strip() and new_code.strip():

                comparison = compare_code_versions(
                    old_code,
                    new_code
                )

        # FIX CODE
        elif action == "fix":

            submitted_code = request.form.get("code", "")
            scanned = True
            fix_requested = True

            if not submitted_code.strip():

                fix_error = "Please enter Python code before requesting a fix."

            else:

                fingerprint = generate_code_fingerprint(submitted_code)
                findings = scan_code(submitted_code)

                impact_map = generate_security_impact_map(
                    submitted_code
                )

                nutrition_label = generate_security_nutrition_label(
                    submitted_code,
                    findings,
                    impact_map
                )

                what_if_result = run_what_if_simulator(
                    findings,
                    impact_map
                )

                try:

                    corrected_code = fix_code_with_ai(
                        submitted_code,
                        findings
                    )

                    if corrected_code.strip():

                        fix_confidence = evaluate_fix_confidence(
                            submitted_code,
                            corrected_code,
                            scan_code
                        )

                    else:

                        fix_error = "The correction returned empty code."

                except Exception as error:

                    app.logger.exception("Code correction failed")
                    fix_error = f"{type(error).__name__}: {str(error)}"

        else:

            fix_error = "Invalid request action."

    return render_template(
        "index.html",

        findings=findings,
        submitted_code=submitted_code,
        fingerprint=fingerprint,
        scanned=scanned,

        comparison=comparison,
        old_code=old_code,
        new_code=new_code,

        corrected_code=corrected_code,
        fix_error=fix_error,
        fix_requested=fix_requested,

        impact_map=impact_map,
        nutrition_label=nutrition_label,

        what_if_result=what_if_result,
        fix_confidence=fix_confidence,
        configuration_report=configuration_report,
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
