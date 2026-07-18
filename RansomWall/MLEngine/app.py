"""
app.py — RansomWall ML Decision Engine (Gradient Tree Boosting)

Chạy:  python app.py
API:   POST http://127.0.0.1:5000/predict
       GET  http://127.0.0.1:5000/health

Input JSON (15 chiều — phải khớp FEATURE_ORDER trong train.py):
    {
        "pid": 1234,
        "unsigned": 1, "packed": 1, "suspicious_strings": 0,
        "honey_modified": 1, "crypto_api": 1,
        "safe_mode_disable": 0, "shadow_deleted": 1, "registry_persist": 0,
        "dir_enum": 1, "high_io": 1, "ext_changed": 1,
        "fingerprint_mismatch": 1, "high_entropy": 1,
        "io_rate": 171.9, "mean_entropy_delta": 2.18
    }

Output JSON:
    {"verdict": "MALWARE"|"BENIGN", "confidence": 0.0-1.0,
     "engine": "gradient_boosting"|"rule-based", "pid": ..., "timestamp": ...}

LƯU Ý:
    - Nếu chưa có model.pkl, engine dùng RULE-BASED fallback để test pipeline.
    - Ngưỡng phán quyết: conf >= 0.5 → MALWARE (ưu tiên Recall).
    - Để bảo vệ đồ án: train trên dataset thật, đưa metrics.txt vào báo cáo.
"""

import os
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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# ── Thứ tự vector 15 chiều — PHẢI khớp với train.py và Features.h::ToJson ──
FEATURE_ORDER = [
    # nhóm A — tĩnh
    "unsigned",             # F1
    "packed",               # F2
    "suspicious_strings",   # F3
    # nhóm C2 — trap
    "honey_modified",       # F4
    "crypto_api",           # F5
    "safe_mode_disable",    # F6
    "shadow_deleted",       # F7
    "registry_persist",     # F8
    # nhóm C3 — động
    "dir_enum",             # F9
    "high_io",              # F10
    "ext_changed",          # F11
    "fingerprint_mismatch", # F12
    "high_entropy",         # F13
    # đặc trưng tốc độ bổ sung
    "io_rate",
    "mean_entropy_delta",
]

N_FEATURES = len(FEATURE_ORDER)  # = 15

# ── Nạp model ──────────────────────────────────────────────────────────────
_model = None
if HAS_SKLEARN and os.path.exists(MODEL_PATH):
    try:
        _model = joblib.load(MODEL_PATH)
        log.info("Da nap model.pkl — GradientBoostingClassifier san sang.")
    except Exception as e:
        log.error("Nap model that bai: %s", e)

if _model is None:
    log.warning("KHONG co model.pkl -> dung RULE-BASED fallback.")
    log.warning("Chay `python train.py` de tao model truoc khi bao ve do an.")


# ── Helpers ────────────────────────────────────────────────────────────────

def to_vector(d: dict) -> list:
    """Chuyển JSON payload → list 15 chiều theo đúng FEATURE_ORDER."""
    return [float(d.get(k, 0) or 0) for k in FEATURE_ORDER]


def rule_based(d: dict):
    """
    Fallback khi chưa có model. KHÔNG phải ML thật —
    chỉ để test pipeline C++ end-to-end trước khi train xong.
    """
    # Bằng chứng MẠNH: gần như chỉ ransomware mới làm
    strong = 0
    if d.get("honey_modified"):         strong += 2
    if d.get("shadow_deleted"):         strong += 2
    if d.get("safe_mode_disable"):      strong += 2
    if d.get("high_entropy"):           strong += 2
    if d.get("fingerprint_mismatch"):   strong += 1
    if d.get("ext_changed"):            strong += 1
    if d.get("registry_persist"):       strong += 1
    if d.get("crypto_api"):             strong += 1

    # Bằng chứng YẾU: nhiều phần mềm lành tính cũng có
    weak = 0
    if d.get("unsigned"):   weak += 1
    if d.get("packed"):     weak += 1
    if d.get("dir_enum"):   weak += 1
    if d.get("high_io"):    weak += 1

    io_rate  = float(d.get("io_rate", 0) or 0)
    d_ent    = float(d.get("mean_entropy_delta", 0) or 0)

    conf  = 0.0
    conf += min(strong / 8.0, 1.0) * 0.55
    conf += min(weak   / 4.0, 1.0) * 0.10
    conf += min(io_rate / 100.0, 1.0) * 0.15
    conf += min(max(d_ent, 0) / 4.0, 1.0) * 0.20
    conf  = min(conf, 1.0)

    verdict = "MALWARE" if (strong >= 4 and conf >= 0.55) else "BENIGN"
    return verdict, conf, {"strong": strong, "weak": weak}


# ── Endpoint /predict ──────────────────────────────────────────────────────

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
            X      = np.array([to_vector(d)])
            proba  = _model.predict_proba(X)[0]
            conf   = float(proba[1])          # P(MALWARE)
            # Ngưỡng 0.5 — ưu tiên Recall: bỏ sót ransomware tốn kém hơn báo nhầm
            verdict = "MALWARE" if conf >= 0.5 else "BENIGN"
            engine  = "gradient_boosting"
            extra   = {}
        except Exception as e:
            log.error("Model loi (%s) -> fallback rule-based", e)
            verdict, conf, extra = rule_based(d)
            engine = "rule-fallback"
    else:
        verdict, conf, extra = rule_based(d)
        engine = "rule-based"

    log.info(
        "PID=%s  io=%.1f  dH=%.2f  ->  %s (%.2f)  [%s]",
        pid,
        float(d.get("io_rate", 0) or 0),
        float(d.get("mean_entropy_delta", 0) or 0),
        verdict, conf, engine,
    )

    resp = {
        "verdict":    verdict,
        "confidence": round(conf, 4),
        "engine":     engine,
        "pid":        pid,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
    }
    resp.update(extra)
    return jsonify(resp)


# ── Endpoint /health ───────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok",
        "model_loaded": _model is not None,
        "engine":       "gradient_boosting" if _model else "rule-based",
        "n_features":   N_FEATURES,
        "features":     FEATURE_ORDER,
    })


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("  RansomWall ML Decision Engine — Gradient Tree Boosting")
    print(f"  Vector: {N_FEATURES} chieu  ({', '.join(FEATURE_ORDER[:4])}...)")
    print(f"  Engine: {'GradientBoosting (model.pkl)' if _model else 'RULE-BASED (chua co model.pkl)'}")
    print("  URL:    http://127.0.0.1:5000/predict")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)