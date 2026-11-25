"""
Hybrid Scanner for SecureCode AI.
Fuses AST Analysis, Source-to-Sink Taint Analysis, Static Security Rules,
and AI/ML Ensemble Classification into an evidence-grounded security engine.
"""

from typing import List, Dict, Any, Tuple, Optional
from .python_ast_scanner import PythonAstScanner
from .javascript_scanner import JavaScriptScanner
from .taint_analyzer import TaintAnalyzer
from .rule_engine import RuleEngine
from .finding_aggregator import FindingAggregator
from .finding_deduplicator import FindingDeduplicator
from .risk_assessment import RiskAssessment, RiskReport
from ml_engine.classifier import vulnerability_classifier


class HybridScanner:
    """Orchestrates multi-technique code security scanning."""

    def __init__(
        self,
        source_code: str,
        language: str = "python",
        file_name: str = "main.py",
        enable_ast: bool = True,
        enable_taint: bool = True,
        enable_rules: bool = True,
        enable_ml: bool = True,
    ):
        self.source_code = source_code
        self.language = language.lower()
        self.file_name = file_name
        self.enable_ast = enable_ast
        self.enable_taint = enable_taint
        self.enable_rules = enable_rules
        self.enable_ml = enable_ml

    def scan(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
        """
        Executes hybrid analysis and returns:
            (findings, ast_summary, risk_report_dict)
        """
        ast_findings: List[Dict[str, Any]] = []
        ast_summary: Dict[str, Any] = {
            "nodesCount": 0,
            "functionsFound": 0,
            "importsFound": [],
            "sinksIdentified": 0,
        }

        # 1. AST Analysis
        if self.enable_ast:
            if self.language == "python":
                scanner = PythonAstScanner(self.source_code, file_name=self.file_name)
                ast_findings, ast_summary = scanner.scan()
            elif self.language in ("javascript", "typescript"):
                scanner = JavaScriptScanner(self.source_code, file_name=self.file_name)
                ast_findings, ast_summary = scanner.scan()

        # 2. Source-to-Sink Taint Analysis
        taint_findings: List[Dict[str, Any]] = []
        if self.enable_taint:
            taint_engine = TaintAnalyzer(self.source_code, file_name=self.file_name, language=self.language)
            taint_findings = taint_engine.analyze()

        # 3. Static Rule Engine
        rule_findings: List[Dict[str, Any]] = []
        if self.enable_rules:
            rule_findings = RuleEngine.evaluate_rules(self.source_code, language=self.language, file_name=self.file_name)

        # 4. Machine Learning Classification
        ml_findings: List[Dict[str, Any]] = []
        if self.enable_ml and vulnerability_classifier.is_ready():
            try:
                raw_ml = vulnerability_classifier.scan_code(self.source_code, self.language, self.file_name)
                # ML serves strictly as a supporting / corroborating detection component.
                # Avoid inventing vulnerability evidence on safe code without structural sink corroboration:
                structural_findings = ast_findings + taint_findings + rule_findings
                if structural_findings:
                    for ml_f in raw_ml:
                        line = ml_f.get("startLine", 1)
                        if any(abs(f.get("startLine", 1) - line) <= 3 for f in structural_findings):
                            ml_findings.append(ml_f)
            except Exception:
                ml_findings = []

        # 5. Evidence Aggregation
        aggregated = FindingAggregator.aggregate(
            ast_findings=ast_findings,
            taint_findings=taint_findings,
            rule_findings=rule_findings,
            ml_findings=ml_findings,
        )

        # 6. Deduplication & Cross-Detector Corroboration
        final_findings = FindingDeduplicator.deduplicate(aggregated)

        # 7. Evidence-based Risk Assessment
        risk_report = RiskAssessment.evaluate_risk(final_findings)

        return final_findings, ast_summary, risk_report.to_dict()
