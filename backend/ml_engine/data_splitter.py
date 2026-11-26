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


PYTHON_JS_KEYWORDS = {
    "import", "from", "def", "class", "return", "if", "else", "elif", "for", "while",
    "try", "except", "with", "as", "in", "is", "not", "and", "or", "true", "false",
    "none", "const", "let", "var", "function", "async", "await", "new", "throw",
    "select", "from", "where", "insert", "into", "update", "delete", "drop",
    "execute", "system", "popen", "run", "loads", "safe_load", "eval", "exec",
    "md5", "sha1", "sha256", "innerhtml", "textcontent", "open", "basename",
    "abspath", "resolve", "getenv", "environ", "env", "mktemp", "debug",
}


def generate_pattern_signature(code: str) -> str:
    """
    Computes a canonical signature for a code snippet by normalizing string literals
    and non-keyword variable identifiers while preserving API sinks & keywords.
    """
    normalized = re.sub(r'["\'][^"\']*["\']', "STR_LITERAL", code)

    def _replace_ident(match: re.Match) -> str:
        tok = match.group(0)
        return tok.lower() if tok.lower() in PYTHON_JS_KEYWORDS else "VAR"

    normalized = re.sub(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', _replace_ident, normalized)
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

        # Stratify groups by majority (isVulnerable, cwe) label so Train/Val/Test
        # preserve class & CWE distribution while keeping groups strictly disjoint.
        strata: Dict[Tuple[int, str], List[str]] = {}
        for gid in sorted(unique_groups):
            group_items = group_map[gid]
            vuln_count = sum(1 if it.get("isVulnerable") else 0 for it in group_items)
            majority_vuln = 1 if vuln_count >= (len(group_items) / 2) else 0
            cwe_label = next(
                (it.get("cwe", "NONE") for it in group_items if it.get("isVulnerable") and it.get("cwe", "NONE") != "NONE"),
                "NONE",
            )
            strata.setdefault((majority_vuln, cwe_label), []).append(gid)

        total_groups = len(unique_groups)
        n_test = max(1, int(round(total_groups * self.test_size)))
        n_val = max(1, int(round(total_groups * self.val_size)))
        n_train = total_groups - n_test - n_val

        if n_train <= 0:
            raise ValueError(f"Too few groups ({total_groups}) for requested test and validation fractions.")

        test_groups_list: List[str] = []
        val_groups_list: List[str] = []
        train_groups_list: List[str] = []

        # Shuffle within each stratum deterministically and allocate across splits
        leftover: List[str] = []
        for stratum_key in sorted(strata.keys()):
            gids = list(strata[stratum_key])
            rng.shuffle(gids)
            k = len(gids)
            if k >= 3:
                s_test = max(1, int(round(k * self.test_size)))
                s_val = max(1, int(round(k * self.val_size)))
                if s_test + s_val >= k:
                    s_test = 1
                    s_val = 1
                test_groups_list.extend(gids[:s_test])
                val_groups_list.extend(gids[s_test : s_test + s_val])
                train_groups_list.extend(gids[s_test + s_val :])
            else:
                leftover.extend(gids)

        # Distribute small-stratum groups while balancing counts toward targets
        rng.shuffle(leftover)
        for gid in leftover:
            if len(test_groups_list) < n_test:
                test_groups_list.append(gid)
            elif len(val_groups_list) < n_val:
                val_groups_list.append(gid)
            else:
                train_groups_list.append(gid)

        # Final count rebalancing if rounding overshot targets slightly
        while len(test_groups_list) > n_test and len(train_groups_list) < n_train:
            train_groups_list.append(test_groups_list.pop())
        while len(val_groups_list) > n_val and len(train_groups_list) < n_train:
            train_groups_list.append(val_groups_list.pop())

        test_groups = set(test_groups_list)
        val_groups = set(val_groups_list)
        train_groups = set(train_groups_list)

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
