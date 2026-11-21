
def generate_security_nutrition_label(code, findings, impact_map=None):
    """
    Generate a security nutrition label from scanner findings.
    """

    findings = findings or []
    impact_map = impact_map or {}

    def get_severity(finding):
        return str(finding.get("severity", "Medium")).lower()

    critical = sum(
        1 for finding in findings
        if get_severity(finding) == "critical"
    )

    high = sum(
        1 for finding in findings
        if get_severity(finding) == "high"
    )

    medium = sum(
        1 for finding in findings
        if get_severity(finding) == "medium"
    )

    low = sum(
        1 for finding in findings
        if get_severity(finding) == "low"
    )

    total = len(findings)

    if critical > 0 or high > 0:
        risk_level = "High"
    elif medium > 0:
        risk_level = "Medium"
    elif low > 0:
        risk_level = "Low"
    else:
        risk_level = "No detected issues"

    summary = impact_map.get("summary", {})

    recommendations = []

    for finding in findings:
        recommendation = finding.get(
            "recommendation",
            "Review this security finding."
        )

        if recommendation not in recommendations:
            recommendations.append(recommendation)

    return {
        "risk_level": risk_level,
        "total_issues": total,
        "critical_issues": critical,
        "high_issues": high,
        "medium_issues": medium,
        "low_issues": low,
        "input_sources": summary.get("input_sources", 0),
        "sensitive_operations": summary.get(
            "sensitive_operations", 0
        ),
        "potential_risk_paths": summary.get(
            "potential_risk_paths", 0
        ),
        "recommendations": recommendations,
        "disclaimer": (
            "This label summarizes detected patterns. "
            "It does not guarantee that the code is secure."
        ),
    }
