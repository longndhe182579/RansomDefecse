from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.utils.class_weight import compute_sample_weight

ROOT = Path(__file__).resolve().parents[2]
LONG = ROOT
DATA = ROOT / "data" / "final"
MODELS = ROOT / "model" / "artifacts"
AUDIT = ROOT / "audit"
for directory in (DATA, MODELS, AUDIT):
    directory.mkdir(parents=True, exist_ok=True)

REMOVED_FEATURES = ["cow_files", "cow_failed", "quota_used"]
FEATURES = [
    "f1_unsigned", "f2_packed", "f3_susp_strings", "f5_crypto_api",
    "f6_safe_mode", "f4_honey", "f7_shadow_del", "f8_reg_persist",
    "f9_dir_enum", "f10_high_io", "f11_ext_changed", "f12_fingerprint",
    "f13_entropy", "f14_daa", "io_rate", "rename_rate", "dirent_rate",
    "entropy_delta_mean", "entropy_delta_max", "entropy_samples", "daa_min",
    "affected_ext_count", "new_ext_max", "backup_entries", "t_ms",
]
THRESHOLD = 0.5
SEED = 20260811


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classifier_for(model_name: str):
    if model_name == "GTB":
        return GradientBoostingClassifier(
            n_estimators=260, learning_rate=.025, max_depth=3,
            min_samples_leaf=25, subsample=.75, random_state=12,
        )
    if model_name == "LGBM":
        return lgb.LGBMClassifier(
            n_estimators=260, learning_rate=.025, max_depth=4, num_leaves=11,
            min_child_samples=30, reg_alpha=1.2, reg_lambda=3.0,
            colsample_bytree=.65, random_state=14, verbose=-1, n_jobs=-1,
        )
    raise ValueError(f"Unknown model: {model_name}")


def select_threshold_oof(model_name, x_train, y_train):
    """Select threshold from five-fold OOF train probabilities; never touch test.csv."""
    splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    probabilities = np.zeros(len(y_train), dtype=float)
    for fold, (fit_indexes, validation_indexes) in enumerate(splitter.split(x_train, y_train), start=1):
        classifier = classifier_for(model_name)
        pipeline = Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", classifier)])
        fold_weights = compute_sample_weight("balanced", y_train.iloc[fit_indexes])
        pipeline.fit(
            x_train.iloc[fit_indexes], y_train.iloc[fit_indexes],
            classifier__sample_weight=fold_weights,
        )
        probabilities[validation_indexes] = pipeline.predict_proba(x_train.iloc[validation_indexes])[:, 1]
    rows = []
    y_array = y_train.to_numpy(int)
    for threshold in np.round(np.arange(.05, .951, .005), 3):
        prediction = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_array, prediction, labels=[0, 1]).ravel()
        rows.append({
            "threshold": float(threshold), "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
            "f1": float(f1_score(y_array, prediction, zero_division=0)),
            "balanced_accuracy": float(balanced_accuracy_score(y_array, prediction)),
            "precision": float(precision_score(y_array, prediction, zero_division=0)),
            "recall": float(recall_score(y_array, prediction, zero_division=0)),
            "specificity": float(tn / (tn + fp)) if tn + fp else 0.0,
            "distance_to_0_5": abs(float(threshold) - .5),
        })
    sweep = pd.DataFrame(rows).sort_values(
        ["f1", "recall", "specificity", "distance_to_0_5"],
        ascending=[False, False, False, True],
    ).reset_index(drop=True)
    selected = float(sweep.iloc[0].threshold)
    sweep.insert(0, "selected", sweep.threshold.eq(selected))
    sweep.to_csv(AUDIT / f"threshold_selection_{model_name.lower()}.csv", index=False)
    return selected, sweep.iloc[0].to_dict()


def train_one(model_name: str):
    train_path = DATA / "train.csv"
    if not train_path.exists():
        raise FileNotFoundError("Run prepare_dataset_v4.py before training")
    train = pd.read_csv(train_path, low_memory=False)
    missing = sorted(set(FEATURES + ["y"]) - set(train.columns))
    if missing:
        raise RuntimeError(f"train.csv missing columns: {missing}")
    if any(column in train.columns for column in REMOVED_FEATURES):
        raise RuntimeError("Removed COW features are still present")
    x_train = train[FEATURES].apply(pd.to_numeric, errors="coerce")
    y_train = train.y.astype(int)
    weights = compute_sample_weight("balanced", y_train)
    selected_threshold, threshold_metrics = select_threshold_oof(model_name, x_train, y_train)
    classifier = classifier_for(model_name)
    pipeline = Pipeline([("imputer", SimpleImputer(strategy="median")), ("classifier", classifier)])
    pipeline.fit(x_train, y_train, classifier__sample_weight=weights)
    stem = model_name.lower()
    model_directory = MODELS / stem
    model_directory.mkdir(parents=True, exist_ok=True)
    model_path = model_directory / "model.pkl"
    joblib.dump({
        "model": pipeline, "model_name": model_name, "version": "V4",
        "features": FEATURES, "removed_features": REMOVED_FEATURES,
        "threshold": selected_threshold, "gateway": "total_score >= 6",
        "total_score_is_feature": False,
    }, model_path)
    sidecar = {
        "model": model_name, "version": "V4", "feature_count": len(FEATURES),
        "features": FEATURES, "removed_features": REMOVED_FEATURES,
        "threshold": selected_threshold,
        "threshold_policy": "maximize 5-fold OOF train F1; ties: recall, specificity, distance to 0.5; test never used",
        "threshold_oof_metrics": threshold_metrics,
        "imputation": "median fitted on train only", "parameters": classifier.get_params(),
        "train_file": str(train_path), "train_sha256": sha256(train_path),
        "model_sha256": sha256(model_path),
    }
    (model_directory / "model.json").write_text(
        json.dumps(sidecar, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    return model_path
