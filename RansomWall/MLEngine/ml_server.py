"""
ml_server.py -- Flask server nhan feature vector tu RansomWall (MLClient.h)
va tra ve verdict malware/benign.

Chay trong Windows VM:
    pip install flask lightgbm joblib numpy
    python ml_server.py --model model_lgbm.pkl --port 5000

RansomWall gui POST /predict voi JSON tu ToJson() (sau khi sua).
Server map ten field -> feature names cua model -> predict -> tra JSON.
"""

import argparse
import logging
import numpy as np
from flask import Flask, request, jsonify
import joblib

app = Flask(__name__)
model = None
FEATURES = None

# Map tu ten field trong ToJson() -> ten feature trong model
FIELD_MAP = {
    "unsigned":           "f1_unsigned",
    "packed":             "f2_packed",
    "suspicious_strings": "f3_susp_strings",
    "honey_modified":     "f4_honey",
    "crypto_api":         "f5_crypto_api",
    "safe_mode_disable":  "f6_safe_mode",
    "shadow_deleted":     "f7_shadow_del",
    "registry_persist":   "f8_reg_persist",
    "dir_enum":           "f9_dir_enum",
    "high_io":            "f10_high_io",
    "ext_changed":        "f11_ext_changed",
    "fingerprint_mismatch":"f12_fingerprint",
    "high_entropy":       "f13_entropy",
    "daa_encrypted":      "f14_daa",
    # Continuous features -- them vao ToJson() sau khi sua
    "io_rate":            "io_rate",
    "rename_rate":        "rename_rate",
    "dirent_rate":        "dirent_rate",
    "entropy_delta_mean": "entropy_delta_mean",
    "entropy_delta_max":  "entropy_delta_max",
    "entropy_samples":    "entropy_samples",
    "daa_min":            "daa_min",
    "cow_files":          "cow_files",
    "cow_failed":         "cow_failed",
    "affected_ext_count": "affected_ext_count",
    "new_ext_max":        "new_ext_max",
    "backup_entries":     "backup_entries",
    "quota_used":         "quota_used",
    "t_ms":               "t_ms",
}

THRESHOLD = 0.5  # nguong predict malware


@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"verdict": "unknown", "confidence": 0.0,
                            "error": "empty body"}), 400

        # Build feature vector
        row = {}
        for src, dst in FIELD_MAP.items():
            v = data.get(src, data.get(dst, 0))
            try:
                row[dst] = float(v)
            except (TypeError, ValueError):
                row[dst] = 0.0

        # Daa_min: gia tri sentinel 9999 nghia la chua tinh duoc -> dat 0
        if row.get("daa_min", 0) > 1000:
            row["daa_min"] = 0.0

        # Xay dung vector theo dung thu tu FEATURES cua model
        X = np.array([[row.get(f, 0.0) for f in FEATURES]], dtype=np.float32)

        prob = float(model.predict_proba(X)[0][1])
        verdict = "malware" if prob >= THRESHOLD else "benign"

        logging.info("PID=%s score=%s prob=%.3f -> %s",
                     data.get("pid", "?"), data.get("total_score", "?"),
                     prob, verdict)

        return jsonify({
            "verdict":    verdict,
            "confidence": round(prob, 4),
            "threshold":  THRESHOLD,
        })

    except Exception as e:
        logging.exception("Predict error")
        return jsonify({"verdict": "unknown", "confidence": 0.0,
                        "error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "features": len(FEATURES)})


def main():
    global model, FEATURES, THRESHOLD

    ap = argparse.ArgumentParser()
    ap.add_argument("--model",     default="model_lgbm.pkl")
    ap.add_argument("--port",      type=int, default=5000)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--host",      default="127.0.0.1")
    args = ap.parse_args()

    THRESHOLD = args.threshold

    print(f"[ML] Load model: {args.model}")
    model = joblib.load(args.model)

    # Doc danh sach features tu model (luu trong json)
    import json, pathlib
    json_path = pathlib.Path(args.model).with_suffix(".json")
    if json_path.exists():
        info = json.loads(json_path.read_text())
        FEATURES = info.get("features", [])
        print(f"[ML] Features tu model.json: {len(FEATURES)}")
    else:
        # Fallback: dung danh sach mac dinh
        FEATURES = [
            "f1_unsigned","f2_packed","f3_susp_strings","f4_honey",
            "f5_crypto_api","f6_safe_mode","f7_shadow_del","f8_reg_persist",
            "f9_dir_enum","f10_high_io","f11_ext_changed","f12_fingerprint",
            "f13_entropy","f14_daa",
            "io_rate","rename_rate","dirent_rate",
            "entropy_delta_mean","entropy_delta_max","entropy_samples",
            "daa_min","cow_files","cow_failed",
            "affected_ext_count","new_ext_max",
            "backup_entries","quota_used","t_ms",
        ]
        print(f"[ML] Dung features mac dinh: {len(FEATURES)}")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )
    print(f"[ML] Server tai http://{args.host}:{args.port}/predict")
    print(f"[ML] Nguong malware: {THRESHOLD}")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()