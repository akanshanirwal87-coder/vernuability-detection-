"""
Model Evaluation Engine for SecureCode AI.
Calculates rigorous, truthful performance metrics for both:
1. Binary Vulnerability Detection (Accuracy, Precision, Recall, F1, PR-AUC, ROC-AUC, Confusion Matrix).
2. Multi-Class CWE Weakness Classification (Accuracy, Macro/Weighted F1, Per-Class Breakdowns).
Never fabricates metrics.
"""

from typing import Dict, Any, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    precision_recall_curve,
    auc,
)


class ModelEvaluator:
    """
    Computes comprehensive evaluation metrics on validation or test partitions.
    """

    @staticmethod
    def evaluate_binary_detector(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: Optional[np.ndarray] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates the binary vulnerability detector (0=Safe, 1=Vulnerable).
        """
        acc = float(accuracy_score(y_true, y_pred))
        prec, rec, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="weighted", zero_division=0
        )

        cm = confusion_matrix(y_true, y_pred).tolist()

        # Calculate PR-AUC and ROC-AUC if probability estimates are available
        pr_auc = None
        roc_auc = None
        if y_prob is not None and len(np.unique(y_true)) > 1:
            try:
                precisions, recalls, _ = precision_recall_curve(y_true, y_prob)
                pr_auc = float(auc(recalls, precisions))
            except Exception:
                pr_auc = None

            try:
                roc_auc = float(roc_auc_score(y_true, y_prob))
            except Exception:
                roc_auc = None

        return {
            "accuracy": round(acc * 100.0, 2),
            "precision": round(float(prec) * 100.0, 2),
            "recall": round(float(rec) * 100.0, 2),
            "f1Score": round(float(f1) * 100.0, 2),
            "macroPrecision": round(float(macro_prec) * 100.0, 2),
            "macroRecall": round(float(macro_rec) * 100.0, 2),
            "macroF1": round(float(macro_f1) * 100.0, 2),
            "weightedF1": round(float(weighted_f1) * 100.0, 2),
            "confusionMatrix": cm,
            "prAuc": round(float(pr_auc) * 100.0, 2) if pr_auc is not None else None,
            "rocAuc": round(float(roc_auc) * 100.0, 2) if roc_auc is not None else None,
            "totalEvaluated": int(len(y_true)),
        }

    @staticmethod
    def evaluate_cwe_classifier(
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> Dict[str, Any]:
        """
        Evaluates the multi-class CWE weakness classifier.
        """
        acc = float(accuracy_score(y_true, y_pred))
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="macro", zero_division=0
        )
        weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="weighted", zero_division=0
        )

        labels = sorted(list(set(y_true) | set(y_pred)))
        per_class_prec, per_class_rec, per_class_f1, support = precision_recall_fscore_support(
            y_true, y_pred, labels=labels, zero_division=0
        )

        per_class_breakdown: Dict[str, Dict[str, float]] = {}
        for idx, label in enumerate(labels):
            per_class_breakdown[str(label)] = {
                "precision": round(float(per_class_prec[idx]) * 100.0, 2),
                "recall": round(float(per_class_rec[idx]) * 100.0, 2),
                "f1Score": round(float(per_class_f1[idx]) * 100.0, 2),
                "support": int(support[idx]),
            }

        cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()

        return {
            "cweAccuracy": round(acc * 100.0, 2),
            "macroPrecision": round(float(macro_prec) * 100.0, 2),
            "macroRecall": round(float(macro_rec) * 100.0, 2),
            "macroF1": round(float(macro_f1) * 100.0, 2),
            "weightedF1": round(float(weighted_f1) * 100.0, 2),
            "classes": labels,
            "perClassMetrics": per_class_breakdown,
            "confusionMatrix": cm,
            "totalEvaluated": int(len(y_true)),
        }
