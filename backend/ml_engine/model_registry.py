"""
Model Registry & Version Manager for SecureCode AI.
Handles atomic artifact persistence, automated backups, SHA-256 artifact checksums,
and comprehensive metadata registration.
"""

import os
import json
import shutil
import hashlib
import joblib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple


class ModelRegistry:
    """
    Manages serialized model weights, checksums, and version metadata.
    """

    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            self.model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
        else:
            self.model_dir = model_dir

        self.backup_dir = os.path.join(self.model_dir, "backups")
        os.makedirs(self.model_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        self.vec_path = os.path.join(self.model_dir, "vectorizer.pkl")
        self.det_path = os.path.join(self.model_dir, "vuln_detector.pkl")
        self.cwe_path = os.path.join(self.model_dir, "cwe_classifier.pkl")
        self.metrics_path = os.path.join(self.model_dir, "model_metrics.json")

    @staticmethod
    def compute_sha256(filepath: str) -> str:
        """Computes SHA-256 hash of a file on disk."""
        if not os.path.exists(filepath):
            return ""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def backup_current_models(self) -> str:
        """
        Creates a timestamped snapshot of current model artifacts before overwriting.
        Returns the snapshot directory path.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_dir = os.path.join(self.backup_dir, f"snapshot_{timestamp}")
        os.makedirs(snapshot_dir, exist_ok=True)

        for filename in ["vectorizer.pkl", "vuln_detector.pkl", "cwe_classifier.pkl", "model_metrics.json"]:
            src = os.path.join(self.model_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(snapshot_dir, filename))

        return snapshot_dir

    def rollback_to_snapshot(self, snapshot_dir: str) -> bool:
        """Restores artifacts from a previous snapshot."""
        if not os.path.exists(snapshot_dir):
            return False
        for filename in ["vectorizer.pkl", "vuln_detector.pkl", "cwe_classifier.pkl", "model_metrics.json"]:
            src = os.path.join(snapshot_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(self.model_dir, filename))
        return True

    def save_models(
        self,
        vectorizer: Any,
        vuln_detector: Any,
        cwe_classifier: Any,
        metadata: Dict[str, Any],
        auto_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Atomically saves the three model artifacts, records SHA-256 checksums,
        and saves model_metrics.json.
        """
        if auto_backup and any(os.path.exists(p) for p in [self.vec_path, self.det_path, self.cwe_path]):
            self.backup_current_models()

        # Temporary files for atomic commit
        tmp_vec = self.vec_path + ".tmp"
        tmp_det = self.det_path + ".tmp"
        tmp_cwe = self.cwe_path + ".tmp"

        joblib.dump(vectorizer, tmp_vec)
        joblib.dump(vuln_detector, tmp_det)
        joblib.dump(cwe_classifier, tmp_cwe)

        os.replace(tmp_vec, self.vec_path)
        os.replace(tmp_det, self.det_path)
        os.replace(tmp_cwe, self.cwe_path)

        # Compute checksums
        checksums = {
            "vectorizer_sha256": self.compute_sha256(self.vec_path),
            "vuln_detector_sha256": self.compute_sha256(self.det_path),
            "cwe_classifier_sha256": self.compute_sha256(self.cwe_path),
        }
        metadata["artifactChecksums"] = checksums
        metadata["savedAt"] = datetime.now(timezone.utc).isoformat()

        # Save metadata JSON
        tmp_metrics = self.metrics_path + ".tmp"
        with open(tmp_metrics, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        os.replace(tmp_metrics, self.metrics_path)

        return metadata

    def load_metrics(self) -> Optional[Dict[str, Any]]:
        """Loads the current model metadata and performance metrics."""
        if not os.path.exists(self.metrics_path):
            return None
        try:
            with open(self.metrics_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
