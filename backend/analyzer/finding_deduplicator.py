"""
Finding Deduplicator for SecureCode AI.
Fuses overlapping findings across detection engines to eliminate duplicates
while preserving the most specific dataflow evidence and identifying all contributing detectors.
"""

from typing import List, Dict, Any
from .confidence_engine import ConfidenceEngine


class FindingDeduplicator:
    """Merges duplicate findings originating from multiple detectors for the same code weakness."""

    @classmethod
    def _is_match(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> bool:
        """Determines if two findings represent the same code vulnerability."""
        # Must be in the same file
        if f1.get("file") != f2.get("file"):
            return False

        # Line overlap check
        s1, e1 = f1.get("startLine", 1), f1.get("endLine", 1)
        s2, e2 = f2.get("startLine", 1), f2.get("endLine", 1)
        lines_overlap = not (e1 < s2 or e2 < s1)
        lines_adjacent = abs(s1 - s2) <= 3

        if not (lines_overlap or lines_adjacent):
            return False

        # Category or CWE compatibility
        c1, c2 = f1.get("cwe"), f2.get("cwe")
        cat1, cat2 = f1.get("category"), f2.get("category")

        if c1 == c2:
            return True
        if cat1 and cat2 and cat1 == cat2:
            return True

        # Related injection overlap (e.g. CWE-78 command injection and CWE-95 eval)
        if {c1, c2}.issubset({"CWE-78", "CWE-95"}):
            return True

        return False

    @classmethod
    def _merge_pair(cls, primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
        """Merges two matching findings into one high-quality consolidated finding."""
        merged = dict(primary)

        # Merge detection methods
        methods1 = list(primary.get("detectionMethods", [primary.get("detectionSource", "AST")]))
        methods2 = list(secondary.get("detectionMethods", [secondary.get("detectionSource", "AST")]))
        all_methods = list(dict.fromkeys(methods1 + methods2))
        merged["detectionMethods"] = all_methods

        # Set compound detectionSource
        if "TAINT_ANALYSIS" in all_methods and "AST" in all_methods:
            merged["detectionSource"] = "HYBRID_TAINT_AND_AST"
        elif "AST" in all_methods and "ML_MODEL" in all_methods:
            merged["detectionSource"] = "HYBRID_AST_AND_ML"
        elif len(all_methods) > 1:
            merged["detectionSource"] = "HYBRID_MULTI_DETECTOR"

        # Prefer finding with explicit dataFlow steps
        if secondary.get("dataFlow") and not primary.get("dataFlow"):
            merged["dataFlow"] = secondary["dataFlow"]

        # Recalculate calibrated confidence
        has_flow = bool(merged.get("dataFlow"))
        cal_conf, rationale = ConfidenceEngine.evaluate_confidence(
            cwe=merged.get("cwe", "CWE-OTHER"),
            detection_methods=all_methods,
            has_dataflow_trace=has_flow,
            has_direct_source=has_flow,
            is_exact_sink_match=True,
            raw_confidence=max(primary.get("confidence", 0.85), secondary.get("confidence", 0.85)),
        )
        merged["confidence"] = cal_conf
        merged["confidenceRationale"] = rationale

        # Expand line boundaries if needed
        merged["startLine"] = min(primary.get("startLine", 1), secondary.get("startLine", 1))
        merged["endLine"] = max(primary.get("endLine", 1), secondary.get("endLine", 1))

        # Merge references
        refs = list(dict.fromkeys(primary.get("references", []) + secondary.get("references", [])))
        merged["references"] = refs

        return merged

    @classmethod
    def deduplicate(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicates a list of findings, returning only unique, consolidated findings."""
        if not findings:
            return []

        # Sort so that TAINT_ANALYSIS findings come first (they possess rich dataflow traces)
        def priority(f: Dict[str, Any]) -> int:
            src = f.get("detectionSource", "")
            if src == "TAINT_ANALYSIS":
                return 0
            if src == "AST":
                return 1
            if src == "STATIC_RULES":
                return 2
            return 3

        sorted_findings = sorted(findings, key=priority)
        deduped: List[Dict[str, Any]] = []

        for candidate in sorted_findings:
            matched = False
            for idx, existing in enumerate(deduped):
                if cls._is_match(existing, candidate):
                    deduped[idx] = cls._merge_pair(existing, candidate)
                    matched = True
                    break
            if not matched:
                deduped.append(candidate)

        return deduped
