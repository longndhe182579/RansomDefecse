"""
app.py — RansomWall ML Decision Engine

Chạy:  python app.py
API:   POST http://127.0.0.1:5000/predict

Input:  feature vector 17 chiều (xem Features.h::ToJson)
Output: {"verdict": "MALWARE"|"BENIGN", "confidence": 0.0-1.0, ...}

LƯU Ý CHO BÁO CÁO:
  - Nếu chưa có model.pkl, engine tự động dùng RULE-BASED fallback.
    Điều này cho phép test toàn bộ pipeline C++ ngay lập tức.
  - Để bảo vệ đồ án bạn PHẢI train trên dataset thật và đưa
    confusion matrix + precision/recall/F1 vào báo cáo (mục 6.3).
  - Ưu tiên RECALL hơn PRECISION: bỏ sót ransomware = mất dữ liệu,
    báo động nhầm = user xác nhận một lần.
"""

import os
import json
import logging
from datetime import datetime

from flask import Flask, request, jsonify

try:
    import joblib
    import numpy as np
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

app = Flask(__name__)
log = logging.getLogger("ransomwall")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# Thứ tự PHẢI khớp với train.py và Features.h::ToJson
FEATURE_ORDER = [
    "unsigned", "packed", "suspicious_strings",
    "honey_modified", "crypto_api", "safe_mode_disable",
    "shadow_deleted", "registry_persist",
    "dir_enum", "high_io", "ext_changed",
    "fingerprint_mismatch", "high_entropy",
    "io_rate", "rename_rate", "affected_ext_count", "mean_entropy_delta",
]

_model = None
if HAS_SKLEARN and os.path.exists(MODEL_PATH):
    try:
        _model = joblib.load(MODEL_PATH)
        log.info("Da nap model.pkl — dung Random Forest.")
    except Exception as e:
        log.error("Nap model that bai: %s", e)

if _model is None:
    log.warning("KHONG co model.pkl -> dung RULE-BASED fallback.")
    log.warning("Chay `python train.py` de tao model truoc khi bao ve do an.")


def to_vector(d):
    return [float(d.get(k, 0) or 0) for k in FEATURE_ORDER]


def rule_based(d):
    """
    Fallback khi chua co model. KHONG phai ML that —
    chi de test pipeline C++ end-to-end.
    """
    score = int(d.get("score", 0) or 0)

    # Bang chung MANH: kho co the la lanh tinh
    strong = 0
    if d.get("honey_modified"):        strong += 2   # user that khong cham honey file
    if d.get("shadow_deleted"):        strong += 2   # gan nhu chi ransomware lam
    if d.get("safe_mode_disable"):     strong += 2
    if d.get("high_entropy"):          strong += 2   # dH > 2.0, khong phai nguong tuyet doi
    if d.get("fingerprint_mismatch"):  strong += 1
    if d.get("ext_changed"):           strong += 1
    if d.get("registry_persist"):      strong += 1
    if d.get("crypto_api"):            strong += 1

    # Bang chung YEU: rat nhieu phan mem lanh tinh cung co
    weak = 0
    if d.get("unsigned"):  weak += 1   # phan mem noi bo / ma nguon mo
    if d.get("packed"):    weak += 1   # installer thuong bi pack
    if d.get("dir_enum"):  weak += 1   # trinh index, backup agent
    if d.get("high_io"):   weak += 1   # 7-Zip, compiler

    io_rate = float(d.get("io_rate", 0) or 0)
    rn_rate = float(d.get("rename_rate", 0) or 0)
    n_ext = float(d.get("affected_ext_count", 0) or 0)
    d_ent = float(d.get("mean_entropy_delta", 0) or 0)

    conf = 0.0
    conf += min(strong / 8.0, 1.0) * 0.50
    conf += min(weak / 4.0, 1.0) * 0.10
    conf += min(io_rate / 100.0, 1.0) * 0.10
    conf += min(rn_rate / 50.0, 1.0) * 0.10
    conf += min(n_ext / 10.0, 1.0) * 0.05
    conf += min(max(d_ent, 0) / 4.0, 1.0) * 0.15
    conf = min(conf, 1.0)

    verdict = "MALWARE" if (strong >= 4 and conf >= 0.55) else "BENIGN"
    return verdict, conf, {"strong": strong, "weak": weak}


@app.route("/predict", methods=["POST"])
def predict():
    try:
        d = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"verdict": "BENIGN", "confidence": 0.0,
                        "error": "invalid json"}), 400

    pid = d.get("pid", 0)

    if _model is not None:
        try:
            X = np.array([to_vector(d)])
            proba = _model.predict_proba(X)[0]
            conf = float(proba[1])
            # Nguong 0.5 uu tien RECALL (bo sot ransomware ton hon bao dong nham)
            verdict = "MALWARE" if conf >= 0.5 else "BENIGN"
            engine = "randomforest"
            extra = {}
        except Exception as e:
            log.error("Model loi (%s) -> fallback rule-based", e)
            verdict, conf, extra = rule_based(d)
            engine = "rule-fallback"
    else:
        verdict, conf, extra = rule_based(d)
        engine = "rule-based"

    log.info("PID=%s score=%s io=%.1f rn=%.1f dH=%.2f -> %s (%.2f) [%s]",
             pid, d.get("score"),
             float(d.get("io_rate", 0) or 0),
             float(d.get("rename_rate", 0) or 0),
             float(d.get("mean_entropy_delta", 0) or 0),
             verdict, conf, engine)

    resp = {
        "verdict": verdict,
        "confidence": round(conf, 4),
        "engine": engine,
        "pid": pid,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    resp.update(extra)
    return jsonify(resp)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": _model is not None,
        "engine": "randomforest" if _model else "rule-based",
        "features": len(FEATURE_ORDER),
    })


if __name__ == "__main__":
    print()
    print("  RansomWall ML Decision Engine")
    print("  http://127.0.0.1:5000/predict")
    print("  Engine:", "RandomForest" if _model else "RULE-BASED (chua co model.pkl)")
    print()
    # threaded=True: nhieu PID co the goi cung luc
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
