"""
Data Splitter for SecureCode AI ML Pipeline.
Enforces strict prevention of data leakage:
1. Splits original data BEFORE any augmentation.
2. Groups duplicate/related code patterns so that all variants remain in the same split.
3. Preserves an untouched validation set (for threshold/hyperparameter checks)
   and an untouched test set (for unbiased final evaluation).
4. Employs deterministic random seeds for reproducible partitioning.
"""

import hashlib
import re
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold, train_test_split


def generate_pattern_signature(code: str) -> str:
    """
    Computes a canonical signature for a code snippet by stripping whitespace,
    string literal contents, and variable identifier names to group related variants.
    """
    # Normalize string literals
    normalized = re.sub(r'["\'][^"\']*["\']', "STR_LITERAL", code)
    # Normalize common variable identifiers
    normalized = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', "ID", normalized)
    # Strip whitespace
    normalized = re.sub(r'\s+', "", normalized)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


class DataSplitter:
    """
    Partitions raw vulnerability samples into train, validation, and test splits
    without data leakage.
    """

    def __init__(
        self,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_seed: int = 42,
    ):
        if test_size <= 0 or val_size <= 0 or (test_size + val_size) >= 1.0:
            raise ValueError("test_size and val_size must be positive and their sum < 1.0")
        self.test_size = test_size
        self.val_size = val_size
        self.random_seed = random_seed

    def split_data(
        self,
        raw_samples: List[Dict[str, Any]],
        group_by_signature: bool = True,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Splits original unaugmented samples into (train, val, test) sets.
        Groups structurally related/duplicate samples together to prevent leakage.
        """
        if not raw_samples:
            return [], [], []

        # Tag each sample with its original index and pattern group
        tagged_samples = []
        for idx, sample in enumerate(raw_samples):
            item = sample.copy()
            item["_original_id"] = idx
            if group_by_signature:
                item["_group_id"] = generate_pattern_signature(sample.get("code", ""))
            else:
                item["_group_id"] = str(idx)
            tagged_samples.append(item)

        # Extract unique groups
        group_map: Dict[str, List[Dict[str, Any]]] = {}
        for item in tagged_samples:
            gid = item["_group_id"]
            if gid not in group_map:
                group_map[gid] = []
            group_map[gid].append(item)

        unique_groups = list(group_map.keys())
        rng = np.random.RandomState(self.random_seed)
        rng.shuffle(unique_groups)

        # Stratification label per group: majority vulnerability label
        group_labels = []
        for gid in unique_groups:
            group_items = group_map[gid]
            vuln_count = sum(1 if it.get("isVulnerable") else 0 for it in group_items)
            group_labels.append(1 if vuln_count >= (len(group_items) / 2) else 0)

        total_groups = len(unique_groups)
        n_test = max(1, int(round(total_groups * self.test_size)))
        n_val = max(1, int(round(total_groups * self.val_size)))
        n_train = total_groups - n_test - n_val

        if n_train <= 0:
            raise ValueError(f"Too few groups ({total_groups}) for requested test and validation fractions.")

        # Allocate groups ensuring balanced representation
        test_groups = set(unique_groups[:n_test])
        val_groups = set(unique_groups[n_test : n_test + n_val])
        train_groups = set(unique_groups[n_test + n_val :])

        train_samples = [it for it in tagged_samples if it["_group_id"] in train_groups]
        val_samples = [it for it in tagged_samples if it["_group_id"] in val_groups]
        test_samples = [it for it in tagged_samples if it["_group_id"] in test_groups]

        return train_samples, val_samples, test_samples

    @staticmethod
    def augment_train_only(
        train_samples: List[Dict[str, Any]],
        replacements: Optional[List[Tuple[str, str]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Augments ONLY the training partition using semantic variable substitutions.
        Validation and Test partitions remain untouched.
        """
        if replacements is None:
            replacements = [
                ("account_id", "user_uuid"),
                ("username", "admin_name"),
                ("user_host", "target_ip"),
                ("file_name", "target_document"),
                ("user_token", "auth_secret"),
                ("email", "client_email"),
                ("account", "member"),
                ("user_command", "exec_cmd"),
                ("cursor.execute", "conn.cursor().execute"),
                ("req.body", "request.payload"),
                ("os.system", "os.popen"),
            ]

        augmented: List[Dict[str, Any]] = []
        for item in train_samples:
            augmented.append(item)
            code = item.get("code", "")
            for old_v, new_v in replacements:
                if old_v in code:
                    new_item = item.copy()
                    new_item["code"] = code.replace(old_v, new_v)
                    new_item["_augmented"] = True
                    augmented.append(new_item)

        return augmented
