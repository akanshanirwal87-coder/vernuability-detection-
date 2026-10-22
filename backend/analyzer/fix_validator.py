import ast
from typing import Dict, Any, Tuple
from .python_ast_scanner import PythonAstScanner
from .javascript_scanner import JavaScriptScanner

class FixValidator:
    @staticmethod
    def validate_python_fix(original_source: str, proposed_code: str, target_finding: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Validates a proposed code fix:
        1. Checks Python syntax validity of proposed snippet.
        2. Checks whether target vulnerability is eliminated.
        3. Returns (passed: bool, status: str, message: str)
        """
        # Step 1: Check syntax
        try:
            ast.parse(proposed_code)
        except SyntaxError as e:
            return False, "VALIDATION_FAILED", f"Proposed fix contains syntax error: {e.msg} on line {e.lineno}"

        # Step 2: Run AST security scanner on the proposed snippet
        scanner = PythonAstScanner(proposed_code, file_name="remediation_test.py")
        findings, _ = scanner.scan()

        # Check if same vulnerability category is still present
        target_category = target_finding.get("category")
        persistent = [f for f in findings if f.get("category") == target_category]
        if persistent:
            return False, "VALIDATION_FAILED", f"Proposed fix still triggers {target_category} in static AST analysis."

        # Check if new critical/high vulnerabilities were introduced
        criticals = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if criticals:
            return False, "VALIDATION_FAILED", f"Fix introduced a new finding: {criticals[0]['title']}"

        return True, "VALIDATION_PASSED", f"AST analysis passed: {target_category} eliminated with zero syntax or static security defects."

    @staticmethod
    def validate_javascript_fix(original_source: str, proposed_code: str, target_finding: Dict[str, Any]) -> Tuple[bool, str, str]:
        scanner = JavaScriptScanner(proposed_code, file_name="remediation_test.js")
        findings, _ = scanner.scan()
        target_category = target_finding.get("category")
        persistent = [f for f in findings if f.get("category") == target_category]
        if persistent:
            return False, "VALIDATION_FAILED", f"Proposed code still contains {target_category} patterns."
        return True, "VALIDATION_PASSED", f"Static verification passed: {target_category} resolved."

