# SecureCode AI — Machine Learning Vulnerability Classification

## 1. Overview

SecureCode AI incorporates a leak-free Machine Learning ensemble (`SecureCode-VulnNet v2.1`) trained on curated, verified vulnerability samples from **OSV.dev (Google / OpenSSF)** and **ManageEngine Endpoint Central Security** baselines.

> [!NOTE]
> **Non-Hallucination Principle**: Machine learning functions strictly as an evidence-corroborating and classification component. The ML model is never permitted to invent vulnerability findings on safe code without structural AST or taint sink evidence.

---

## 2. Feature Extraction Architecture

The feature extraction pipeline (`backend/ml_engine/feature_extractor.py`) combines lexical code representations with semantic domain security features:

1. **Sublinear TF-IDF N-Grams (1 to 3 words)**: Extracts token syntax, method invocations, and identifier patterns (vocabulary cap: 4,000 features).
2. **17 Structural Security Sinks & Guards**:
   - `has_dynamic_interpolation`: Presence of `+`, f-strings, `.format()`, or `%`.
   - `has_sql_keywords`: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`.
   - `has_parameterized_query`: Placeholders (`?`, `%s`, `$1`, `:id`).
   - `has_shell_exec_sink`: `shell=True`, `os.system`, `child_process.exec`.
   - `has_safe_process_exec`: `shell=False`, `subprocess.run([...])`.
   - `has_unsafe_deserializer`: `pickle.loads`, `yaml.load`, `marshal`.
   - `has_safe_deserializer`: `json.loads`, `yaml.safe_load`, `literal_eval`.
   - `has_insecure_crypto`: `md5`, `sha1`, `DES`, `ARC4`.
   - `has_secure_crypto`: `sha256`, `sha512`, `argon2`, `bcrypt`.
   - `has_dom_xss_sink`: `innerHTML`, `document.write`, `outerHTML`.
   - `has_safe_dom_sink`: `textContent`, `innerText`, `DOMPurify`.
   - `has_path_traversal_sink`: `open()`, `fs.readFile()` without guards.
   - `has_path_containment`: `basename()`, `abspath()`, `startswith()`.
   - `has_hardcoded_secret`: Token/secret assignment patterns.
   - `has_env_secret_retrieval`: `os.getenv()`, `process.env`.
   - `has_osv_package_pattern`: Known CVE library imports.
   - `has_manageengine_endpoint_rule`: ManageEngine endpoint baseline rules.

---

## 3. Data Leakage Prevention Strategy

To ensure scientific integrity:
1. **Pre-Split Grouping**: Original code samples are partitioned into **Train (70%)**, **Validation (15%)**, and **Test (15%)** sets using signature grouping before any data augmentation.
2. **Train-Only Augmentation**: Semantic variable renaming and formatting augmentation are applied strictly to the training partition.
3. **Untouched Test Set**: Validation and test sets remain 100% unaugmented and unseen during model fitting.
4. **Vocabulary Isolation**: The TF-IDF vectorizer vocabulary is fit exclusively on the training corpus.

---

## 4. Empirical Model Benchmark Comparison

All candidate models were evaluated on the exact same untouched test partition (Random Seed: 42, Dataset Hash: `34d3bbb332c66583`):

| Model Architecture | Accuracy | Precision | Recall | F1 Score | False Positive Rate (FPR) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression (C=5.0)** | **92.59%** | **87.50%** | **95.45%** | **91.30%** | **9.38%** | Benchmark Candidate |
| **Random Forest (150 Trees)** | 46.30% | 42.22% | 86.36% | 56.72% | 81.25% | Baseline |
| **Linear SVM (Calibrated)** | 77.78% | 65.62% | 95.45% | 77.78% | 34.38% | Benchmark Candidate |
| **Calibrated Ensemble (RF + LR)** | 77.78% | 65.62% | 95.45% | 77.78% | 34.38% | Production Classifier |

### Multi-Class CWE Classifier Performance:
- **CWE Classification Accuracy**: **88.89%**
- **Macro F1 Score**: **78.30%**
- Evaluated classes: `CWE-89` (SQLi), `CWE-78` (Command Injection), `CWE-22` (Path Traversal), `CWE-502` (Deserialization), `CWE-798` (Secrets), `CWE-327` (Crypto), `CWE-79` (XSS), `CWE-1321` (Prototype Pollution).
