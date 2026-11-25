"""
Confidence Engine for SecureCode AI.
Calculates calibrated confidence scores (0.0 to 1.0) and rationale for vulnerability findings.
Avoids artificial confidence inflation when multiple detectors share the exact same underlying syntax evidence.
"""

from typing import List, Dict, Any, Tuple


class ConfidenceEngine:
    """Evaluates and calibrates finding confidence based on evidence quality and corroboration."""

    @classmethod
    def evaluate_confidence(
        cls,
        cwe: str,
        detection_methods: List[str],
        has_dataflow_trace: bool,
        has_direct_source: bool,
        is_exact_sink_match: bool,
        raw_confidence: float = 0.85,
    ) -> Tuple[float, str]:
        """
        Calculates calibrated confidence and returns (calibrated_score, rationale).
        """
        methods_set = set(detection_methods)
        reasons = []

        base = raw_confidence

        # Taint analysis with full verified source-to-sink trace is highest confidence
        if "TAINT_ANALYSIS" in methods_set and has_dataflow_trace:
            base = max(base, 0.95)
            reasons.append("Full source-to-sink dataflow trace verified by taint analyzer.")

        # Static AST sink match
        if "AST" in methods_set:
            if is_exact_sink_match:
                reasons.append("Dangerous sink pattern confirmed in Abstract Syntax Tree.")

        # Multi-detector corroboration (calibrated boost without artificial inflation)
        if len(methods_set) >= 2:
            # If both AST and ML, or Taint and Rules corroborate:
            if "TAINT_ANALYSIS" in methods_set and "AST" in methods_set:
                base = min(0.98, base + 0.02)
                reasons.append("Corroborated by both dataflow taint propagation and AST syntax inspection.")
            elif "ML_MODEL" in methods_set and ("AST" in methods_set or "TAINT_ANALYSIS" in methods_set):
                base = min(0.97, base + 0.02)
                reasons.append("Corroborated by AI/ML semantic feature classification.")

        # ML alone without structural sink confirmation is bounded
        if methods_set == {"ML_MODEL"}:
            base = min(0.85, base)
            reasons.append("Standalone AI/ML prediction without AST sink confirmation.")

        final_conf = round(min(0.99, max(0.50, base)), 2)
        rationale = " ".join(reasons) if reasons else "Single detector confidence estimate."
        return final_conf, rationale
