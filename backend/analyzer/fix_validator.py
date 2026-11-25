"""
Fix Validator for SecureCode AI.
Multi-stage automated remediation verification engine:
1. Syntax validation (AST parsing).
2. Target vulnerability elimination check.
3. Regression verification (checks that no new security flaws were introduced).
Explicit statuses:
- SUGGESTED
- SYNTAX_VALID
- SECURITY_CHECK_PASSED
- REGRESSION_TESTS_PASSED
- VERIFICATION_FAILED
Never claims a fix is secure based only on syntax validation.
"""

import ast
from dataclasses import dataclass, field
from typing import Dict, Any, Tuple, List, Optional
from .patch_generator import PatchGenerator
from .regression_checker import RegressionChecker
from .python_ast_scanner import PythonAstScanner
from .javascript_scanner import JavaScriptScanner


@dataclass
class VerificationReport:
    finding_id: str
    target_cwe: str
    status: str  # "SUGGESTED", "SYNTAX_VALID", "SECURITY_CHECK_PASSED", "REGRESSION_TESTS_PASSED", "VERIFICATION_FAILED"
    passed: bool
    message: str
    syntax_valid: bool
    vulnerability_fixed: bool
    regression_free: bool
    unified_diff: str = ""
    new_findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findingId": self.finding_id,
            "targetCwe": self.target_cwe,
            "status": self.status,
            "passed": self.passed,
            "message": self.message,
            "syntaxValid": self.syntax_valid,
            "vulnerabilityFixed": self.vulnerability_fixed,
            "regressionFree": self.regression_free,
            "unifiedDiff": self.unified_diff,
            "newFindings": self.new_findings,
        }


class FixValidator:
    """Automated sandbox verification of proposed remediation fixes."""

    @classmethod
    def verify_remediation(
        cls,
        original_source: str,
        proposed_code: str,
        target_finding: Dict[str, Any],
        language: str = "python",
    ) -> VerificationReport:
        """
        Executes the full 3-stage verification pipeline on proposed remediation:
        Stage 1: Syntax compilation
        Stage 2: Static security re-scan
        Stage 3: Regression checking
        """
        finding_id = target_finding.get("id", "fnd-unknown")
        target_cwe = target_finding.get("cwe", "CWE-OTHER")
        start_line = target_finding.get("startLine", 1)
        end_line = target_finding.get("endLine", start_line)
        lang = language.lower()

        # Generate patched code buffer and unified diff
        patched_code, diff_str = PatchGenerator.generate_patch(
            original_code=original_source,
            start_line=start_line,
            end_line=end_line,
            replacement_snippet=proposed_code,
            file_name=target_finding.get("file", "main.py"),
        )

        # Stage 1: Syntax Validation
        if lang == "python":
            import textwrap
            try:
                ast.parse(textwrap.dedent(proposed_code))
                # If original source was valid Python syntax, verify patched code compiles
                is_orig_valid = True
                try:
                    ast.parse(original_source)
                except SyntaxError:
                    is_orig_valid = False

                if is_orig_valid:
                    ast.parse(patched_code)
            except SyntaxError as e:
                return VerificationReport(
                    finding_id=finding_id,
                    target_cwe=target_cwe,
                    status="VERIFICATION_FAILED",
                    passed=False,
                    message=f"Syntax Error in proposed fix: {e.msg} on line {e.lineno}",
                    syntax_valid=False,
                    vulnerability_fixed=False,
                    regression_free=False,
                    unified_diff=diff_str,
                )
        else:
            # Basic JS bracket balance validation
            opens = proposed_code.count("{") + proposed_code.count("(") + proposed_code.count("[")
            closes = proposed_code.count("}") + proposed_code.count(")") + proposed_code.count("]")
            if opens != closes:
                return VerificationReport(
                    finding_id=finding_id,
                    target_cwe=target_cwe,
                    status="VERIFICATION_FAILED",
                    passed=False,
                    message="Syntax Error in JavaScript fix: Unbalanced braces or parentheses.",
                    syntax_valid=False,
                    vulnerability_fixed=False,
                    regression_free=False,
                    unified_diff=diff_str,
                )

        # Stage 2 & 3: Security Check & Regression Check
        target_eliminated, regression_free, new_findings, msg = RegressionChecker.check_regression(
            patched_code=patched_code,
            target_cwe=target_cwe,
            original_findings=[target_finding],
            language=lang,
            file_name=target_finding.get("file", "patched_source"),
        )

        if not target_eliminated:
            return VerificationReport(
                finding_id=finding_id,
                target_cwe=target_cwe,
                status="VERIFICATION_FAILED",
                passed=False,
                message=f"Security check failed: {target_cwe} is still present in the patched code.",
                syntax_valid=True,
                vulnerability_fixed=False,
                regression_free=regression_free,
                unified_diff=diff_str,
                new_findings=new_findings,
            )

        if not regression_free:
            return VerificationReport(
                finding_id=finding_id,
                target_cwe=target_cwe,
                status="VERIFICATION_FAILED",
                passed=False,
                message=f"Regression detected: Fix introduced {len(new_findings)} new security finding(s).",
                syntax_valid=True,
                vulnerability_fixed=True,
                regression_free=False,
                unified_diff=diff_str,
                new_findings=new_findings,
            )

        # Both security check and regression check passed!
        return VerificationReport(
            finding_id=finding_id,
            target_cwe=target_cwe,
            status="REGRESSION_TESTS_PASSED",
            passed=True,
            message=f"Verification successful: {target_cwe} eliminated with zero security regressions.",
            syntax_valid=True,
            vulnerability_fixed=True,
            regression_free=True,
            unified_diff=diff_str,
            new_findings=[],
        )

    # Backward-compatible helper methods for existing service calls
    @classmethod
    def validate_python_fix(
        cls, original_source: str, proposed_code: str, target_finding: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        report = cls.verify_remediation(
            original_source=original_source,
            proposed_code=proposed_code,
            target_finding=target_finding,
            language="python",
        )
        status = "VALIDATION_PASSED" if report.passed else report.status
        return report.passed, status, report.message

    @classmethod
    def validate_javascript_fix(
        cls, original_source: str, proposed_code: str, target_finding: Dict[str, Any]
    ) -> Tuple[bool, str, str]:
        report = cls.verify_remediation(
            original_source=original_source,
            proposed_code=proposed_code,
            target_finding=target_finding,
            language="javascript",
        )
        status = "VALIDATION_PASSED" if report.passed else report.status
        return report.passed, status, report.message
