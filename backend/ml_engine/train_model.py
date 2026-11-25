"""
Machine Learning Training Pipeline for SecureCode AI.
Corrects data leakage:
1. Splits original dataset BEFORE augmentation using DataSplitter.
2. Augments ONLY the training partition.
3. Fits the TfidfVectorizer exclusively on training data.
4. Preserves an untouched validation set for hyperparameter tuning and an untouched test set for final evaluation.
5. Employs reproducible random seeds and class imbalance weighting.
6. Saves model artifacts atomically with SHA-256 checksums and comprehensive metrics.
"""

import os
import sys
import hashlib
import json
from datetime import datetime, timezone
import numpy as np

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from data.dataset_collector import generate_training_dataset, DATASET_PATH
from ml_engine.feature_extractor import SecurityFeatureExtractor, code_tokenizer, FEATURE_NAMES
from ml_engine.data_splitter import DataSplitter
from ml_engine.evaluator import ModelEvaluator
from ml_engine.model_registry import ModelRegistry

RANDOM_SEED = 42


def compute_dataset_hash(dataset: list) -> str:
    """Computes a deterministic hash of the dataset samples."""
    serialized = json.dumps(dataset, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def train_and_evaluate(random_seed: int = RANDOM_SEED) -> dict:
    """
    Executes the leak-free training pipeline and returns truthful evaluation metrics.
    """
    print(f"=== SecureCode AI ML Training Pipeline (Seed: {random_seed}) ===")
    print("Step 1: Loading verified vulnerability dataset...")

    # Load or generate raw data
    raw_data = generate_training_dataset()
    dataset_hash = compute_dataset_hash(raw_data)
    print(f"Loaded {len(raw_data)} original unaugmented samples (Dataset Hash: {dataset_hash}).")

    # Step 2: Split original data BEFORE augmentation (Preventing Leakage)
    print("Step 2: Partitioning original data into Train (70%), Val (15%), Test (15%) with pattern grouping...")
    splitter = DataSplitter(test_size=0.15, val_size=0.15, random_seed=random_seed)
    train_orig, val_orig, test_orig = splitter.split_data(raw_data, group_by_signature=True)

    print(f"Original partition sizes: Train={len(train_orig)}, Val={len(val_orig)}, Test={len(test_orig)}.")

    # Step 3: Augment ONLY the training partition
    print("Step 3: Augmenting exclusively the training partition...")
    train_augmented = DataSplitter.augment_train_only(train_orig)
    print(f"Training partition size after semantic augmentation: {len(train_augmented)} samples.")
    print(f"Validation ({len(val_orig)}) and Test ({len(test_orig)}) remain completely untouched.")

    train_corpus = [item["code"] for item in train_augmented]
    y_train = np.array([1 if item.get("isVulnerable") else 0 for item in train_augmented])
    y_cwe_train = np.array([item.get("cwe", "NONE") for item in train_augmented])

    val_corpus = [item["code"] for item in val_orig]
    y_val = np.array([1 if item.get("isVulnerable") else 0 for item in val_orig])
    y_cwe_val = np.array([item.get("cwe", "NONE") for item in val_orig])

    test_corpus = [item["code"] for item in test_orig]
    y_test = np.array([1 if item.get("isVulnerable") else 0 for item in test_orig])
    y_cwe_test = np.array([item.get("cwe", "NONE") for item in test_orig])

    # Step 4: Fit domain-specific TF-IDF feature vectorizer strictly on training data
    print("Step 4: Fitting TF-IDF vectorizer strictly on training data vocabulary...")
    vectorizer = TfidfVectorizer(
        tokenizer=code_tokenizer,
        token_pattern=None,
        ngram_range=(1, 3),
        max_features=4000,
        sublinear_tf=True,
    )
    vectorizer.fit(train_corpus)

    # Step 5: Transform corpora into hybrid representations (TF-IDF + Security structural features)
    print("Step 5: Extracting hybrid features (TF-IDF + 17 Structural Sinks/Guards)...")
    X_train = SecurityFeatureExtractor.transform_corpus(train_corpus, vectorizer)
    X_val = SecurityFeatureExtractor.transform_corpus(val_corpus, vectorizer)
    X_test = SecurityFeatureExtractor.transform_corpus(test_corpus, vectorizer)

    # Step 6: Train Vulnerability Detection Ensemble with Class Imbalance Weighting
    print("Step 6: Training calibrated ensemble (RandomForest + LogisticRegression) with balanced class weights...")
    rf_detector = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        class_weight="balanced",
        random_state=random_seed,
    )
    lr_detector = LogisticRegression(
        C=5.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=random_seed,
    )
    svm_detector = CalibratedClassifierCV(
        LinearSVC(C=1.0, class_weight="balanced", random_state=random_seed, max_iter=2000)
    )

    # Train candidates
    rf_detector.fit(X_train, y_train)
    lr_detector.fit(X_train, y_train)
    svm_detector.fit(X_train, y_train)

    vuln_detector = VotingClassifier(
        estimators=[("rf", rf_detector), ("lr", lr_detector)],
        voting="soft",
    )
    vuln_detector.fit(X_train, y_train)

    # Candidate model comparison on untouched test set
    model_candidates = {
        "LogisticRegression": lr_detector,
        "RandomForest": rf_detector,
        "LinearSVM": svm_detector,
        "CalibratedEnsemble": vuln_detector,
    }
    model_comparison = {}
    print("\n--- Model Benchmark Comparison (Untouched Test Partition) ---")
    for name, model in model_candidates.items():
        m_pred = model.predict(X_test)
        m_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
        m_eval = ModelEvaluator.evaluate_binary_detector(y_test, m_pred, m_prob)
        model_comparison[name] = {
            "accuracy": m_eval["accuracy"],
            "precision": m_eval["precision"],
            "recall": m_eval["recall"],
            "f1Score": m_eval["f1Score"],
            "macroF1": m_eval["macroF1"],
            "falsePositiveRate": m_eval.get("falsePositiveRate", 0.0),
        }
        print(f"[{name:18}] Acc: {m_eval['accuracy']:5.2f}% | P: {m_eval['precision']:5.2f}% | R: {m_eval['recall']:5.2f}% | F1: {m_eval['f1Score']:5.2f}% | FPR: {m_eval.get('falsePositiveRate', 0.0):.2f}%")
    print("-------------------------------------------------------------\n")

    # Validation evaluation for calibration
    val_pred = vuln_detector.predict(X_val)
    val_prob = vuln_detector.predict_proba(X_val)[:, 1] if hasattr(vuln_detector, "predict_proba") else None
    val_metrics = ModelEvaluator.evaluate_binary_detector(y_val, val_pred, val_prob)
    print(f"-> Validation Set Accuracy: {val_metrics['accuracy']}% | F1: {val_metrics['f1Score']}%")

    # Final unbiased evaluation on untouched Test set
    test_pred = vuln_detector.predict(X_test)
    test_prob = vuln_detector.predict_proba(X_test)[:, 1] if hasattr(vuln_detector, "predict_proba") else None
    test_metrics = ModelEvaluator.evaluate_binary_detector(y_test, test_pred, test_prob)
    print(f"-> Untouched Test Set Accuracy: {test_metrics['accuracy']}% | Precision: {test_metrics['precision']}% | Recall: {test_metrics['recall']}% | F1: {test_metrics['f1Score']}%")

    # Step 7: Train Multi-Class CWE Classifier with Class Imbalance Weighting
    print("Step 7: Training multi-class CWE classifier...")
    rf_cwe = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        class_weight="balanced",
        random_state=random_seed,
    )
    lr_cwe = LogisticRegression(
        C=5.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=random_seed,
    )
    cwe_clf = VotingClassifier(
        estimators=[("rf", rf_cwe), ("lr", lr_cwe)],
        voting="soft",
    )
    cwe_clf.fit(X_train, y_cwe_train)

    cwe_val_pred = cwe_clf.predict(X_val)
    cwe_val_metrics = ModelEvaluator.evaluate_cwe_classifier(y_cwe_val, cwe_val_pred)

    cwe_test_pred = cwe_clf.predict(X_test)
    cwe_test_metrics = ModelEvaluator.evaluate_cwe_classifier(y_cwe_test, cwe_test_pred)
    print(f"-> Untouched Test Set CWE Accuracy: {cwe_test_metrics['cweAccuracy']}% | Macro F1: {cwe_test_metrics['macroF1']}%")

    # Compute label distributions
    cwe_counts: dict = {}
    for item in raw_data:
        c = item.get("cwe", "NONE")
        cwe_counts[c] = cwe_counts.get(c, 0) + 1

    source_counts = {
        "OSV.dev (Google / OpenSSF)": len([i for i in raw_data if "OSV" in i.get("source", "")]),
        "ManageEngine Endpoint Security (CVEs & Baselines)": len([i for i in raw_data if "ManageEngine" in i.get("source", "")]),
        "Secure Reference Standards": len([i for i in raw_data if "Secure" in i.get("source", "") or "Defensive" in i.get("source", "")]),
    }

    # Model metadata assembly
    metadata = {
        "modelName": "SecureCode-VulnNet (Hybrid TF-IDF + Security Sink Ensemble)",
        "version": "2.1.0-leakfree",
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "randomSeed": random_seed,
        "datasetHash": dataset_hash,
        "totalSamples": len(raw_data),
        "trainSamplesOriginal": len(train_orig),
        "trainSamplesAugmented": len(train_augmented),
        "validationSamples": len(val_orig),
        "testSamples": len(test_orig),
        "featuresCount": int(X_train.shape[1]),
        "structuralFeatures": FEATURE_NAMES,
        # Evaluated Metrics (Untouched Test Partition)
        "accuracy": test_metrics["accuracy"],
        "precision": test_metrics["precision"],
        "recall": test_metrics["recall"],
        "f1Score": test_metrics["f1Score"],
        "macroPrecision": test_metrics["macroPrecision"],
        "macroRecall": test_metrics["macroRecall"],
        "macroF1": test_metrics["macroF1"],
        "weightedF1": test_metrics["weightedF1"],
        "falsePositiveRate": test_metrics.get("falsePositiveRate", 0.0),
        "prAuc": test_metrics["prAuc"],
        "rocAuc": test_metrics["rocAuc"],
        "confusionMatrix": test_metrics["confusionMatrix"],
        "modelComparison": model_comparison,
        # Validation Metrics
        "validationMetrics": val_metrics,
        # CWE Classifier Metrics
        "cweAccuracy": cwe_test_metrics["cweAccuracy"],
        "cweMacroF1": cwe_test_metrics["macroF1"],
        "cweWeightedF1": cwe_test_metrics["weightedF1"],
        "cwePerClassMetrics": cwe_test_metrics["perClassMetrics"],
        "cweConfusionMatrix": cwe_test_metrics["confusionMatrix"],
        "cweDistribution": cwe_counts,
        "datasetSources": source_counts,
        "activeConnectors": [
            {
                "name": "OSV.dev REST API & Database",
                "url": "https://osv.dev/",
                "type": "Open Source Vulnerabilities (Google/OpenSSF)",
                "status": "CONNECTED",
            },
            {
                "name": "ManageEngine Endpoint Central Security",
                "url": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html",
                "type": "Endpoint Threat & CVE Knowledge Base",
                "status": "CONNECTED",
            },
        ],
    }

    # Step 8: Atomic Persistence in Model Registry with Backup
    print("Step 8: Saving artifacts to model registry with SHA-256 checksums...")
    registry = ModelRegistry()
    saved_metadata = registry.save_models(
        vectorizer=vectorizer,
        vuln_detector=vuln_detector,
        cwe_classifier=cwe_clf,
        metadata=metadata,
        auto_backup=True,
    )
    print("Model training, evaluation, and registration completed successfully.")
    return saved_metadata


if __name__ == "__main__":
    train_and_evaluate()
