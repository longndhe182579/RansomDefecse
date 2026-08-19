"""Flask inference server for RansomDefense GTB/LightGBM bundles.

Deployment files placed in this directory:
    model.joblib
    metadata.json

The decision threshold, ordered features and preprocessing are loaded from the
trained artifact. No probability threshold is hard-coded in this server.
Only load joblib files produced by a trusted training pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, request


app = Flask(__name__)
MODEL: Any = None
IMPUTER: Any = None
FEATURES: list[str] = []
THRESHOLD: float | None = None
MODEL_NAME = "unknown"
MODEL_PATH: Path | None = None
METADATA_PATH: Path | None = None

FIELD_MAP = {
    "unsigned": "f1_unsigned",
    "packed": "f2_packed",
    "suspicious_strings": "f3_susp_strings",
    "honey_modified": "f4_honey",
    "crypto_api": "f5_crypto_api",
    "safe_mode_disable": "f6_safe_mode",
    "shadow_deleted": "f7_shadow_del",
    "registry_persist": "f8_reg_persist",
    "dir_enum": "f9_dir_enum",
    "high_io": "f10_high_io",
    "ext_changed": "f11_ext_changed",
    "fingerprint_mismatch": "f12_fingerprint",
    "high_entropy": "f13_entropy",
    "daa_encrypted": "f14_daa",
    "io_rate": "io_rate",
    "rename_rate": "rename_rate",
    "dirent_rate": "dirent_rate",
    "entropy_delta_mean": "entropy_delta_mean",
    "entropy_delta_max": "entropy_delta_max",
    "entropy_samples": "entropy_samples",
    "daa_min": "daa_min",
    "affected_ext_count": "affected_ext_count",
    "new_ext_max": "new_ext_max",
    "backup_entries": "backup_entries",
    "t_ms": "t_ms",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metadata_file_for(model_path: Path, explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit).resolve())
    candidates.extend([
        model_path.parent / "metadata.json",
        model_path.with_suffix(".json"),
    ])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Metadata JSON not found. Copy metadata.json beside model.joblib "
        "or pass --metadata <path>."
    )


def _feature_list(value: Any, source: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x for x in value):
        raise TypeError(f"Invalid feature list in {source}")
    if len(value) != len(set(value)):
        raise ValueError(f"Duplicate feature names in {source}")
    return value


def _numeric_threshold(value: Any, source: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"Invalid threshold in {source}: {value!r}")
    result = float(value)
    if not 0.0 < result < 1.0:
        raise ValueError(f"Threshold from {source} must be between 0 and 1")
    return result


def load_artifacts(model_file: str, metadata_file: str | None = None) -> dict:
    """Load and validate model, preprocessing, feature order and OOF threshold."""
    global MODEL, IMPUTER, FEATURES, THRESHOLD, MODEL_NAME, MODEL_PATH, METADATA_PATH

    model_path = Path(model_file).resolve()
    if not model_path.is_file():
        raise FileNotFoundError(f"Model not found: {model_path}")
    metadata_path = metadata_file_for(model_path, metadata_file)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    if not isinstance(metadata, dict):
        raise TypeError("metadata.json must contain a JSON object")

    expected_hash = str(metadata.get("bundle_sha256", "")).strip().lower()
    actual_hash = sha256(model_path)
    if expected_hash and expected_hash != actual_hash:
        raise ValueError(
            f"Model SHA-256 mismatch: metadata={expected_hash}, actual={actual_hash}"
        )

    loaded = joblib.load(model_path)
    bundle = loaded if isinstance(loaded, dict) else {}
    classifier = loaded
    if bundle:
        classifier = bundle.get("model")
        if classifier is None:
            for key in ("classifier", "clf", "estimator", "lgbm", "booster"):
                if bundle.get(key) is not None:
                    classifier = bundle[key]
                    break
    if classifier is None or not hasattr(classifier, "predict_proba"):
        raise TypeError("Loaded artifact does not contain a classifier with predict_proba")

    imputer = bundle.get("imputer") if bundle else None
    metadata_features = _feature_list(metadata.get("features"), "metadata.json")
    bundle_features = _feature_list(bundle.get("features"), "model bundle") if bundle else None
    if metadata_features and bundle_features and metadata_features != bundle_features:
        raise ValueError("Feature order differs between model bundle and metadata.json")
    features = metadata_features or bundle_features
    if not features:
        raise ValueError("Feature order is missing from both model bundle and metadata.json")
    declared_count = metadata.get("feature_count")
    if declared_count is not None and int(declared_count) != len(features):
        raise ValueError("feature_count does not match the feature list")

    metadata_threshold = _numeric_threshold(metadata.get("threshold"), "metadata.json")
    bundle_threshold = _numeric_threshold(bundle.get("threshold"), "model bundle") if bundle else None
    if metadata_threshold is not None and bundle_threshold is not None and not np.isclose(
        metadata_threshold, bundle_threshold, atol=1e-12
    ):
        raise ValueError("Threshold differs between model bundle and metadata.json")
    threshold = metadata_threshold if metadata_threshold is not None else bundle_threshold
    if threshold is None:
        raise ValueError("Optimized threshold is missing from model bundle and metadata.json")

    MODEL = classifier
    IMPUTER = imputer
    FEATURES = features
    THRESHOLD = threshold
    MODEL_NAME = str(metadata.get("model_name") or bundle.get("model_name") or type(classifier).__name__)
    MODEL_PATH = model_path
    METADATA_PATH = metadata_path
    return {
        "model_name": MODEL_NAME,
        "features": len(FEATURES),
        "threshold": THRESHOLD,
        "model_sha256": actual_hash,
        "model_path": str(MODEL_PATH),
        "metadata_path": str(METADATA_PATH),
        "imputer_loaded": IMPUTER is not None,
    }


def payload_frame(data: dict) -> pd.DataFrame:
    row: dict[str, float] = {}
    for source, feature in FIELD_MAP.items():
        raw = data.get(source, data.get(feature))
        if raw is None or raw == "":
            row[feature] = np.nan
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Feature {source!r} is not numeric: {raw!r}") from exc
        if not np.isfinite(value):
            row[feature] = np.nan
        else:
            row[feature] = value

    # Runtime uses zero when these measurements are not available. Training CSV
    # represents the same state as missing, so restore NaN before train-fitted imputation.
    if row.get("entropy_samples", 0.0) <= 0:
        row["entropy_delta_mean"] = np.nan
    if row.get("daa_min", 0.0) <= 0 or row.get("daa_min", 0.0) > 1000:
        row["daa_min"] = np.nan

    missing_contract = sorted(set(FEATURES) - set(row))
    if missing_contract:
        raise ValueError(f"Server has no payload mapping for model features: {missing_contract}")
    return pd.DataFrame([[row[name] for name in FEATURES]], columns=FEATURES, dtype=float)


@app.route("/predict", methods=["POST"])
def predict():
    if MODEL is None or THRESHOLD is None:
        return jsonify({"verdict": "unknown", "confidence": 0.0, "error": "model not loaded"}), 503
    try:
        data = request.get_json(force=True)
        if not isinstance(data, dict) or not data:
            return jsonify({"verdict": "unknown", "confidence": 0.0, "error": "empty body"}), 400
        frame = payload_frame(data)
        values = IMPUTER.transform(frame) if IMPUTER is not None else frame
        probability = float(MODEL.predict_proba(values)[0][1])
        verdict = "malware" if probability >= THRESHOLD else "benign"
        logging.info(
            "model=%s pid=%s score=%s probability=%.6f threshold=%.6f verdict=%s",
            MODEL_NAME, data.get("pid", "?"), data.get("total_score", "?"),
            probability, THRESHOLD, verdict,
        )
        return jsonify({
            "verdict": verdict,
            "confidence": round(probability, 6),
            "threshold": THRESHOLD,
            "model": MODEL_NAME,
        })
    except ValueError as exc:
        return jsonify({"verdict": "unknown", "confidence": 0.0, "error": str(exc)}), 400
    except Exception as exc:
        logging.exception("Prediction error")
        return jsonify({"verdict": "unknown", "confidence": 0.0, "error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    ready = MODEL is not None and THRESHOLD is not None and bool(FEATURES)
    return jsonify({
        "status": "ok" if ready else "not_ready",
        "model_loaded": ready,
        "model": MODEL_NAME,
        "features": len(FEATURES),
        "threshold": THRESHOLD,
        "imputer_loaded": IMPUTER is not None,
        "model_path": str(MODEL_PATH) if MODEL_PATH else None,
        "metadata_path": str(METADATA_PATH) if METADATA_PATH else None,
    }), 200 if ready else 503


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="model.joblib")
    parser.add_argument("--metadata", default=None)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    loaded = load_artifacts(args.model, args.metadata)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(f"[ML] Model: {loaded['model_name']}")
    print(f"[ML] Features: {loaded['features']}")
    print(f"[ML] Optimized threshold: {loaded['threshold']}")
    print(f"[ML] Imputer loaded: {loaded['imputer_loaded']}")
    print(f"[ML] Server: http://{args.host}:{args.port}/predict")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
