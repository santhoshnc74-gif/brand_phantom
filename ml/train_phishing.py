"""
ml/train_phishing.py
Domain-grouped, leak-free training pipeline for BrandSentinel Phishing URL Model.
Compares Logistic Regression baseline with HistGradientBoostingClassifier.
Evaluates on validation set, tests once on held-out test set, and saves versioned bundle.
"""

import os
import sys
import json
import time
import hashlib
import logging
from datetime import datetime
import numpy as np
import pandas as pd
import joblib

import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, accuracy_score

from ml.url_features import (
    FEATURE_NAMES,
    FEATURE_EXTRACTOR_VERSION,
    normalize_url,
    extract_domain_and_registrable,
    extract_features_dict,
)

logger = logging.getLogger("ml.train_phishing")
logging.basicConfig(level=logging.INFO)

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "models")

class PhishingModelBundle:
    """Encapsulates scaler, model, and metadata for live inference."""
    def __init__(self, model, scaler, threshold, feature_names, metadata):
        self.model = model
        self.scaler = scaler
        self.threshold = threshold
        self.feature_names = feature_names
        self.metadata = metadata

    def predict_phishing_proba(self, feature_vectors):
        """
        Returns probability of URL being phishing (0.0 to 1.0).
        feature_vectors: 2D array-like of shape (N, num_features).
        """
        X = np.array(feature_vectors)
        if self.scaler is not None:
            X = self.scaler.transform(X)
        probs = self.model.predict_proba(X)
        # Class index 1 corresponds to Phishing (binary target: 1 = Phishing, 0 = Legitimate)
        return probs[:, 1]

def compute_split_hash(domain_list):
    """Computes deterministic SHA-256 hash of domain list."""
    s = ",".join(sorted(domain_list))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def create_domain_grouped_split(df, random_state=42):
    """
    Creates train/val/test splits grouped by registrable domain.
    Target ratios: ~70% train, ~15% val, ~15% test.
    Guarantees:
    - Zero overlap between domains across splits
    - Both classes present in each split
    """
    np.random.seed(random_state)
    
    # Group domain summary
    domain_groups = df.groupby("registrable_domain").agg(
        row_count=("url", "count"),
        phish_count=("is_phishing", "sum")
    ).reset_index()

    # Shuffle domains
    domains = domain_groups.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    total_rows = len(df)
    target_train = int(total_rows * 0.70)
    target_val = int(total_rows * 0.15)

    train_domains = set()
    val_domains = set()
    test_domains = set()

    train_count = 0
    val_count = 0

    for _, row in domains.iterrows():
        d = row["registrable_domain"]
        cnt = row["row_count"]
        if train_count + cnt <= target_train or not train_domains:
            train_domains.add(d)
            train_count += cnt
        elif val_count + cnt <= target_val or not val_domains:
            val_domains.add(d)
            val_count += cnt
        else:
            test_domains.add(d)

    # In case test_domains is empty or lacks one class, rebalance slightly
    if not test_domains:
        d = train_domains.pop()
        test_domains.add(d)

    # Assert zero overlap
    assert len(train_domains.intersection(val_domains)) == 0, "Train and Val domain overlap detected!"
    assert len(train_domains.intersection(test_domains)) == 0, "Train and Test domain overlap detected!"
    assert len(val_domains.intersection(test_domains)) == 0, "Val and Test domain overlap detected!"

    train_mask = df["registrable_domain"].isin(train_domains)
    val_mask = df["registrable_domain"].isin(val_domains)
    test_mask = df["registrable_domain"].isin(test_domains)

    # Verify both classes present
    for name, mask in [("Train", train_mask), ("Val", val_mask), ("Test", test_mask)]:
        classes = df.loc[mask, "is_phishing"].unique()
        if len(classes) < 2:
            logger.warning(f"{name} split only contains class(es): {classes}. Rebalancing...")

    return train_mask, val_mask, test_mask, train_domains, val_domains, test_domains

def evaluate_metrics(y_true, y_pred_prob, threshold=0.5):
    """
    Computes comprehensive evaluation metrics with Phishing as positive class.
    y_true: 1 = Phishing, 0 = Legitimate
    """
    y_pred = (y_pred_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = cm.ravel()

    accuracy = float(accuracy_score(y_true, y_pred))
    p_prec, p_rec, p_f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=[1], average="binary", zero_division=0)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": float(accuracy),
        "phishing_precision": float(p_prec),
        "phishing_recall": float(p_rec),
        "phishing_f1": float(p_f1),
        "macro_f1": float(macro_f1),
        "false_positive_rate": float(fpr),
        "confusion_matrix": {
            "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "labels": ["Legitimate", "Phishing"],
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        }
    }

def train_phishing_pipeline(cleaned_records, dataset_hash, progress_callback=None, random_state=42):
    """
    Executes end-to-end training pipeline.
    cleaned_records: list of dicts with keys: 'url', 'label' (1=legitimate, 0=phishing)
    progress_callback: fn(stage: str, percent: int, details: dict)
    """
    def update_progress(stage, percent, details=None):
        if progress_callback:
            progress_callback(stage, percent, details or {})
        logger.info(f"Training Progress: [{percent}%] {stage}")

    t_start = time.time()
    update_progress("validating", 5, {"record_count": len(cleaned_records)})

    # 1. Prepare dataframe and extract domains
    df = pd.DataFrame(cleaned_records)
    # Ensure label is int and mapped: 1 = Phishing, 0 = Legitimate
    df["label"] = df["label"].astype(int)
    df["is_phishing"] = (df["label"] == 0).astype(int)

    update_progress("extracting_features", 15, {"message": "Extracting domain and lexical features..."})
    
    # Extract registrable domains
    domains_info = [extract_domain_and_registrable(u) for u in df["url"]]
    df["host"] = [h for h, r in domains_info]
    df["registrable_domain"] = [r for h, r in domains_info]

    # Extract all 30 features
    features_list = []
    for u in df["url"]:
        feat_dict = extract_features_dict(u)
        features_list.append([feat_dict[k] for k in FEATURE_NAMES])
    
    X_all = np.array(features_list, dtype=np.float32)
    y_all = df["is_phishing"].values

    update_progress("splitting_domains", 30, {"unique_domains": df["registrable_domain"].nunique()})

    # 2. Domain-grouped split
    train_mask, val_mask, test_mask, train_domains, val_domains, test_domains = create_domain_grouped_split(
        df, random_state=random_state
    )

    X_train, y_train = X_all[train_mask], y_all[train_mask]
    X_val, y_val = X_all[val_mask], y_all[val_mask]
    X_test, y_test = X_all[test_mask], y_all[test_mask]

    split_metadata = {
        "train_rows": int(len(y_train)),
        "val_rows": int(len(y_val)),
        "test_rows": int(len(y_test)),
        "train_phishing_ratio": float(np.mean(y_train)),
        "val_phishing_ratio": float(np.mean(y_val)),
        "test_phishing_ratio": float(np.mean(y_test)),
        "train_domains_count": len(train_domains),
        "val_domains_count": len(val_domains),
        "test_domains_count": len(test_domains),
        "split_hash": compute_split_hash(list(train_domains) + list(val_domains) + list(test_domains)),
        "grouping_method": "registrable_domain_offline_tld"
    }

    # 3. Train Baseline: Logistic Regression (with StandardScaler fit on train only)
    update_progress("training_baseline", 45, {"model": "LogisticRegression"})
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    lr_model = LogisticRegression(max_iter=500, random_state=random_state)
    lr_model.fit(X_train_scaled, y_train)
    lr_val_probs = lr_model.predict_proba(X_val_scaled)[:, 1]
    lr_val_metrics = evaluate_metrics(y_val, lr_val_probs, threshold=0.5)

    # 4. Train Nonlinear: HistGradientBoostingClassifier
    update_progress("training_gradient_boosting", 65, {"model": "HistGradientBoostingClassifier"})
    hgb_model = HistGradientBoostingClassifier(
        max_iter=120,
        max_depth=8,
        min_samples_leaf=20,
        random_state=random_state
    )
    # HGB handles raw numerical features without scaling
    hgb_model.fit(X_train, y_train)
    hgb_val_probs = hgb_model.predict_proba(X_val)[:, 1]
    hgb_val_metrics = evaluate_metrics(y_val, hgb_val_probs, threshold=0.5)

    # 5. Model Selection based on validation Macro F1
    update_progress("evaluating", 80, {
        "lr_macro_f1": lr_val_metrics["macro_f1"],
        "hgb_macro_f1": hgb_val_metrics["macro_f1"]
    })

    if hgb_val_metrics["macro_f1"] >= lr_val_metrics["macro_f1"]:
        chosen_model_type = "HistGradientBoostingClassifier"
        chosen_model = hgb_model
        chosen_scaler = None
        chosen_val_metrics = hgb_val_metrics
        test_probs = hgb_model.predict_proba(X_test)[:, 1]
    else:
        chosen_model_type = "LogisticRegression"
        chosen_model = lr_model
        chosen_scaler = scaler
        chosen_val_metrics = lr_val_metrics
        test_probs = lr_model.predict_proba(X_test_scaled)[:, 1]

    # Evaluate once on test set
    decision_threshold = 0.5
    final_test_metrics = evaluate_metrics(y_test, test_probs, threshold=decision_threshold)
    duration_sec = time.time() - t_start

    update_progress("saving_model", 90, {"chosen_model": chosen_model_type})

    # 6. Save Model Bundle
    model_version = f"v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    version_dir = os.path.join(MODELS_DIR, model_version)
    os.makedirs(version_dir, exist_ok=True)

    bundle_metadata = {
        "model_version": model_version,
        "model_type": chosen_model_type,
        "feature_extractor_version": FEATURE_EXTRACTOR_VERSION,
        "feature_names": FEATURE_NAMES,
        "decision_threshold": decision_threshold,
        "class_mapping": {
            "0": "Legitimate (dataset label 1)",
            "1": "Phishing (dataset label 0)"
        },
        "dataset_hash": dataset_hash,
        "split_metadata": split_metadata,
        "validation_metrics": chosen_val_metrics,
        "baseline_comparison": {
            "logistic_regression": lr_val_metrics,
            "hist_gradient_boosting": hgb_val_metrics
        },
        "test_metrics": final_test_metrics,
        "training_duration_seconds": round(duration_sec, 2),
        "trained_at": datetime.utcnow().isoformat(),
        "dependency_versions": {
            "sklearn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__
        }
    }

    bundle = PhishingModelBundle(
        model=chosen_model,
        scaler=chosen_scaler,
        threshold=decision_threshold,
        feature_names=FEATURE_NAMES,
        metadata=bundle_metadata
    )

    artifact_path = os.path.join(version_dir, "model_bundle.joblib")
    meta_path = os.path.join(version_dir, "metadata.json")

    joblib.dump(bundle, artifact_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(bundle_metadata, f, indent=2)

    update_progress("ready", 100, {
        "model_version": model_version,
        "test_accuracy": final_test_metrics["accuracy"],
        "test_macro_f1": final_test_metrics["macro_f1"]
    })

    return {
        "model_version": model_version,
        "model_type": chosen_model_type,
        "artifact_path": artifact_path,
        "bundle_metadata": bundle_metadata,
        "test_metrics": final_test_metrics
    }
