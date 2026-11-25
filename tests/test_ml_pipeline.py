import pytest
import numpy as np
from ml_engine.data_splitter import DataSplitter, generate_pattern_signature
from ml_engine.evaluator import ModelEvaluator
from ml_engine.model_registry import ModelRegistry
from data.dataset_collector import generate_training_dataset


def test_no_data_leakage_between_splits():
    """Verify that sample pattern signatures in train, val, and test partitions are completely disjoint."""
    samples = generate_training_dataset()
    splitter = DataSplitter(test_size=0.15, val_size=0.15, random_seed=42)
    train_set, val_set, test_set = splitter.split_data(samples)

    train_hashes = {generate_pattern_signature(s["code"]) for s in train_set}
    val_hashes = {generate_pattern_signature(s["code"]) for s in val_set}
    test_hashes = {generate_pattern_signature(s["code"]) for s in test_set}

    # Verify zero intersection
    assert len(train_hashes.intersection(val_hashes)) == 0, "Leakage detected between train and val!"
    assert len(train_hashes.intersection(test_hashes)) == 0, "Leakage detected between train and test!"
    assert len(val_hashes.intersection(test_hashes)) == 0, "Leakage detected between val and test!"


def test_evaluation_metrics_binary_truthfulness():
    """Verify binary classification metrics calculate correctly without fabrication."""
    # 3 TP, 1 FP, 1 FN, 5 TN
    y_true = np.array([1, 1, 1, 0, 0, 0, 0, 0, 1, 0])
    y_pred = np.array([1, 1, 1, 1, 0, 0, 0, 0, 0, 0])
    y_proba = np.array([0.9, 0.8, 0.7, 0.6, 0.1, 0.2, 0.3, 0.4, 0.4, 0.2])

    metrics = ModelEvaluator.evaluate_binary_detector(y_true, y_pred, y_proba)

    assert isinstance(metrics, dict)
    assert metrics["accuracy"] == 80.0
    # Precision: 3 / (3 + 1) = 75.0%
    assert metrics["precision"] == 75.0
    # Recall: 3 / (3 + 1) = 75.0%
    assert metrics["recall"] == 75.0
    # F1: 75.0%
    assert metrics["f1Score"] == 75.0
    assert metrics["confusionMatrix"] == [[5, 1], [1, 3]]
    assert metrics["rocAuc"] is not None
    assert metrics["prAuc"] is not None


def test_evaluation_metrics_multiclass():
    """Verify multiclass metrics calculate macro F1, weighted F1, and per-class metrics."""
    y_true = np.array(["CWE-89", "CWE-89", "CWE-79", "CWE-78"])
    y_pred = np.array(["CWE-89", "CWE-89", "CWE-79", "CWE-89"])

    metrics = ModelEvaluator.evaluate_cwe_classifier(y_true, y_pred)
    assert metrics["cweAccuracy"] == 75.0
    assert "CWE-89" in metrics["perClassMetrics"]
    assert "CWE-79" in metrics["perClassMetrics"]
    assert "CWE-78" in metrics["perClassMetrics"]
    assert metrics["macroF1"] > 0
    assert metrics["weightedF1"] > 0


def test_training_reproducibility():
    """Verify that using random seed 42 produces identical data split partitions."""
    samples = generate_training_dataset()
    splitter1 = DataSplitter(random_seed=42)
    splitter2 = DataSplitter(random_seed=42)
    split1 = splitter1.split_data(samples)
    split2 = splitter2.split_data(samples)

    codes1_train = [s["code"] for s in split1[0]]
    codes2_train = [s["code"] for s in split2[0]]
    assert codes1_train == codes2_train, "Data split must be strictly reproducible with identical seed!"
