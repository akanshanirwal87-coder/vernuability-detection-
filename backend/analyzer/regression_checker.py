"""
Regression Checker for SecureCode AI.
Performs before-and-after static security verification on patched code.
Verifies whether the target vulnerability has been resolved and ensures no new security defects are introduced.
"""

from typing import List, Dict, Any, Tuple
from .python_ast_scanner import PythonAstScanner
from .javascript_scanner import JavaScriptScanner


class RegressionChecker:
    """Verifies that code remediation eliminates the target flaw without introducing security regressions."""

    @classmethod
    def check_regression(
        cls,
        patched_code: str,
        target_cwe: str,
        original_findings: List[Dict[str, Any]],
        language: str = "python",
        file_name: str = "patched_source",
    ) -> Tuple[bool, bool, List[Dict[str, Any]], str]:
        """
        Runs security analysis on patched code and compares before vs after.
        Returns:
            (target_eliminated: bool, regression_free: bool, new_findings: List[Dict], message: str)
        """
        lang = language.lower()

        # Run static scanner on patched code
        if lang == "python":
            scanner = PythonAstScanner(patched_code, file_name=file_name)
            new_findings, _ = scanner.scan()
        else:
            scanner = JavaScriptScanner(patched_code, file_name=file_name)
            new_findings, _ = scanner.scan()

        # Check if the target CWE is still present
        norm_target = target_cwe.upper()
        still_present = any(f.get("cwe", "").upper() == norm_target for f in new_findings)
        target_eliminated = not still_present

        # Check if new critical or high findings were introduced
        orig_cwes = {f.get("cwe", "").upper() for f in original_findings}
        introduced = [
            f for f in new_findings
            if f.get("cwe", "").upper() not in orig_cwes and f.get("severity", "LOW") in ("CRITICAL", "HIGH")
        ]

        regression_free = len(introduced) == 0

        if not target_eliminated:
            msg = f"Remediation failed: Target vulnerability {target_cwe} is still detected in patched code."
        elif not regression_free:
            introduced_titles = ", ".join(f["title"] for f in introduced)
            msg = f"Security regression detected: Proposed patch introduced new defect(s): {introduced_titles}."
        else:
            msg = f"Verification passed: {target_cwe} successfully eliminated with zero security regressions."

        return target_eliminated, regression_free, introduced, msg
