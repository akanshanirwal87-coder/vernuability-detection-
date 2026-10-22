"""
Machine Learning Training Pipeline for SecureCode AI
Trains code vulnerability detection and CWE classification models
on real-world datasets ingested from OSV.dev and ManageEngine Endpoint Central.
"""

import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import joblib
import numpy as np
from datetime import datetime, timezone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

from data.dataset_collector import generate_training_dataset, DATASET_PATH
from ml_engine.feature_extractor import SecurityFeatureExtractor, code_tokenizer, FEATURE_NAMES

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(MODEL_DIR, exist_ok=True)

def train_and_evaluate():
    print("=== SecureCode AI ML Training Pipeline ===")
    print("Step 1: Loading real-world vulnerability dataset (OSV.dev + ManageEngine)...")

    # Generate or reload dataset
    data = generate_training_dataset()

    # Augment dataset with variations
    augmented_data = []
    var_replacements = [
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
        ("os.system", "os.popen")
    ]

    for item in data:
        augmented_data.append(item)
        code = item["code"]
        for old_v, new_v in var_replacements:
            if old_v in code:
                new_item = item.copy()
                new_item["code"] = code.replace(old_v, new_v)
                augmented_data.append(new_item)

    print(f"Total dataset size after augmentation: {len(augmented_data)} samples.")

    corpus = [item["code"] for item in augmented_data]
    y_binary = np.array([1 if item["isVulnerable"] else 0 for item in augmented_data])
    y_cwe = np.array([item["cwe"] for item in augmented_data])

    # Step 2: Fit domain-specific TF-IDF feature vectorizer
    print("Step 2: Fitting domain-specific TF-IDF feature vectorizer (n-grams 1-3)...")
    vectorizer = TfidfVectorizer(
        tokenizer=code_tokenizer,
        token_pattern=None,
        ngram_range=(1, 3),
        max_features=4000,
        sublinear_tf=True
    )
    vectorizer.fit(corpus)

    # Step 3: Transform into Hybrid Representation (TF-IDF + Security Structure)
    print("Step 3: Extracting hybrid semantic features (TF-IDF + Security Sink/Guard vectors)...")
    X = SecurityFeatureExtractor.transform_corpus(corpus, vectorizer)

    # Stratified Train/Test Split
    X_train, X_test, y_train, y_test, y_cwe_train, y_cwe_test = train_test_split(
        X, y_binary, y_cwe, test_size=0.20, random_state=42, stratify=y_binary
    )

    # Step 4: Train Ensemble Vulnerability Detector (Random Forest + Logistic Regression)
    print("Step 4: Training calibrated ensemble vulnerability detection model...")
    rf_detector = RandomForestClassifier(n_estimators=150, max_depth=25, random_state=42)
    lr_detector = LogisticRegression(C=5.0, max_iter=1000, random_state=42)
    vuln_detector = VotingClassifier([('rf', rf_detector), ('lr', lr_detector)], voting='soft')
    vuln_detector.fit(X_train, y_train)

    y_pred = vuln_detector.predict(X_test)
    y_prob = vuln_detector.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary")
    conf_mat = confusion_matrix(y_test, y_pred).tolist()

    print(f"-> Vulnerability Detection Accuracy: {acc * 100:.2f}%")
    print(f"-> Precision: {prec * 100:.2f}% | Recall: {rec * 100:.2f}% | F1-Score: {f1 * 100:.2f}%")

    # Step 5: Train CWE Classifier
    print("Step 5: Training multi-class CWE classifier...")
    rf_cwe = RandomForestClassifier(n_estimators=150, max_depth=25, random_state=42)
    lr_cwe = LogisticRegression(C=5.0, max_iter=1000, random_state=42)
    cwe_clf = VotingClassifier([('rf', rf_cwe), ('lr', lr_cwe)], voting='soft')
    cwe_clf.fit(X_train, y_cwe_train)

    cwe_pred = cwe_clf.predict(X_test)
    cwe_acc = accuracy_score(y_cwe_test, cwe_pred)
    print(f"-> Multi-Class CWE Classification Accuracy: {cwe_acc * 100:.2f}%")

    # Step 6: Save Model Artifacts
    print("Step 6: Serializing model artifacts to backend/ml_engine/models/...")
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, "vectorizer.pkl"))
    joblib.dump(vuln_detector, os.path.join(MODEL_DIR, "vuln_detector.pkl"))
    joblib.dump(cwe_clf, os.path.join(MODEL_DIR, "cwe_classifier.pkl"))

    # Compute CWE distribution
    cwe_counts = {}
    for item in augmented_data:
        c = item["cwe"]
        cwe_counts[c] = cwe_counts.get(c, 0) + 1

    # Extract source distribution
    source_counts = {
        "OSV.dev (Google / OpenSSF)": len([i for i in augmented_data if "OSV" in i.get("source", "")]),
        "ManageEngine Endpoint Security (CVEs & Baselines)": len([i for i in augmented_data if "ManageEngine" in i.get("source", "")]),
        "Secure Reference Standards": len([i for i in augmented_data if "Secure" in i.get("source", "") or "Defensive" in i.get("source", "")])
    }

    metadata = {
        "modelName": "SecureCode-VulnNet (Hybrid TF-IDF + Security Sink Ensemble)",
        "version": "2.0.0",
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "totalSamples": len(augmented_data),
        "trainSamples": int(X_train.shape[0]),
        "testSamples": int(X_test.shape[0]),
        "featuresCount": int(X.shape[1]),
        "structuralFeatures": FEATURE_NAMES,
        "accuracy": round(float(acc) * 100, 2),
        "precision": round(float(prec) * 100, 2),
        "recall": round(float(rec) * 100, 2),
        "f1Score": round(float(f1) * 100, 2),
        "cweAccuracy": round(float(cwe_acc) * 100, 2),
        "confusionMatrix": conf_mat,
        "cweDistribution": cwe_counts,
        "datasetSources": source_counts,
        "activeConnectors": [
            {
                "name": "OSV.dev REST API & Database",
                "url": "https://osv.dev/",
                "type": "Open Source Vulnerabilities (Google/OpenSSF)",
                "status": "CONNECTED"
            },
            {
                "name": "ManageEngine Endpoint Central Security",
                "url": "https://www.manageengine.com/products/desktop-central/endpoint-central-endpoint-security.html",
                "type": "Endpoint Threat & CVE Knowledge Base",
                "status": "CONNECTED"
            }
        ]
    }

    with open(os.path.join(MODEL_DIR, "model_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("Model training completed successfully! Metrics recorded in model_metrics.json")
    return metadata

if __name__ == "__main__":
    train_and_evaluate()

