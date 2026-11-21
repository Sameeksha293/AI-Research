
import ast


INPUT_FUNCTIONS = {
    "input",
    "request.args.get",
    "request.form.get",
    "request.values.get",
    "request.get_json",
}

SENSITIVE_FUNCTIONS = {
    "eval": "Dynamic code execution",
    "exec": "Dynamic code execution",
    "os.system": "Operating system command execution",
    "subprocess.call": "Subprocess execution",
    "subprocess.run": "Subprocess execution",
    "subprocess.Popen": "Subprocess execution",
    "cursor.execute": "Database query execution",
    "connection.execute": "Database query execution",
}


def get_call_name(node):

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    return ""


def get_loaded_variables(node):

    variables = set()

    for child in ast.walk(node):

        if isinstance(child, ast.Name):
            if isinstance(child.ctx, ast.Load):
                variables.add(child.id)

    return variables


def get_assigned_variables(node):

    variables = set()

    for child in ast.walk(node):

        if isinstance(child, ast.Name):
            if isinstance(child.ctx, (ast.Store, ast.Param)):
                variables.add(child.id)

    return variables


class SecurityImpactAnalyzer(ast.NodeVisitor):

    def __init__(self):

        self.sources = []
        self.sinks = []
        self.paths = []
        self.findings = []

        self.tainted_variables = set()
        self.source_lines = {}

    def visit_Assign(self, node):

        source_detected = False
        source_line = None

        # Identify user-controlled input
        for child in ast.walk(node.value):

            if isinstance(child, ast.Call):

                function_name = get_call_name(child.func)

                if function_name in INPUT_FUNCTIONS:

                    source_detected = True
                    source_line = child.lineno

                    source = {
                        "type": "User Input",
                        "function": function_name,
                        "line": source_line
                    }

                    if source not in self.sources:
                        self.sources.append(source)

        # FIX: Process each assignment target separately
        assigned_variables = set()

        for target in node.targets:
            assigned_variables.update(
                get_assigned_variables(target)
            )

        used_variables = get_loaded_variables(node.value)

        inherited_taint = (
            used_variables & self.tainted_variables
        )

        is_tainted = source_detected or bool(inherited_taint)

        for variable in assigned_variables:

            if is_tainted:

                self.tainted_variables.add(variable)

                if source_detected:
                    self.source_lines[variable] = source_line

                else:
                    inherited_sources = {
                        self.source_lines.get(name)
                        for name in inherited_taint
                        if self.source_lines.get(name) is not None
                    }

                    self.source_lines[variable] = (
                        min(inherited_sources)
                        if inherited_sources
                        else None
                    )

            else:
                self.tainted_variables.discard(variable)
                self.source_lines.pop(variable, None)

        self.generic_visit(node)

    def visit_Call(self, node):

        function_name = get_call_name(node.func)

        if function_name in SENSITIVE_FUNCTIONS:

            argument_variables = set()

            for argument in node.args:
                argument_variables.update(
                    get_loaded_variables(argument)
                )

            for keyword in node.keywords:
                argument_variables.update(
                    get_loaded_variables(keyword.value)
                )

            affected_variables = (
                argument_variables & self.tainted_variables
            )

            sink = {
                "operation": function_name,
                "description": SENSITIVE_FUNCTIONS[function_name],
                "line": node.lineno,
                "variables": sorted(affected_variables)
            }

            self.sinks.append(sink)

            if affected_variables:

                for variable in sorted(affected_variables):

                    self.paths.append({
                        "source": "User Input",
                        "variable": variable,
                        "destination": function_name,
                        "source_line": self.source_lines.get(variable),
                        "destination_line": node.lineno,
                        "risk": "Potentially unsafe data flow"
                    })

                self.findings.append({
                    "issue": "Untrusted input reaches a sensitive operation",
                    "severity": "High",
                    "line": node.lineno,
                    "operation": function_name,
                    "variables": sorted(affected_variables),
                    "recommendation": (
                        "Validate user-controlled data and avoid "
                        "passing untrusted input to sensitive operations."
                    )
                })

        self.generic_visit(node)


def generate_security_impact_map(code):

    if not isinstance(code, str) or not code.strip():

        return {
            "success": False,
            "error": "Please provide Python code.",
            "sources": [],
            "sinks": [],
            "paths": [],
            "findings": []
        }

    try:

        syntax_tree = ast.parse(code)

        analyzer = SecurityImpactAnalyzer()
        analyzer.visit(syntax_tree)

        return {
            "success": True,
            "sources": analyzer.sources,
            "sinks": analyzer.sinks,
            "paths": analyzer.paths,
            "findings": analyzer.findings,
            "summary": {
                "input_sources": len(analyzer.sources),
                "sensitive_operations": len(analyzer.sinks),
                "potential_risk_paths": len(analyzer.paths),
                "potential_issues": len(analyzer.findings)
            },
            "disclaimer": (
                "Static analysis only. Detected paths are potential "
                "risks, not proof of exploitability. Undetected paths "
                "may still exist."
            )
        }

    except SyntaxError as error:

        return {
            "success": False,
            "error": (
                f"Python syntax error on line {error.lineno}: {error.msg}"
            ),
            "sources": [],
            "sinks": [],
            "paths": [],
            "findings": []
        }
