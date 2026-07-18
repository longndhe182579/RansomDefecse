"""
train.py — Train Gradient Tree Boosting cho RansomWall v4.0

Chạy:
    python train.py                   # sinh dataset tổng hợp, train, lưu model.pkl
    python train.py --real data.csv   # train trên dữ liệu thật

Xuất:
    model.pkl            — model dùng cho app.py
    metrics.txt          — confusion matrix, precision/recall/F1, AUC
    feature_importance.txt

CẢNH BÁO QUAN TRỌNG CHO ĐỒ ÁN:
    Script này sinh DATASET TỔNG HỢP để pipeline chạy được ngay.
    Model train trên dữ liệu tổng hợp KHÔNG có giá trị khoa học.

    Để bảo vệ đồ án bạn PHẢI:
      1. Thu thập mẫu ransomware thật (VirusShare, MalwareBazaar, theZoo)
         và mẫu benign thật (phần mềm phổ biến trên máy)
      2. Chạy từng mẫu trong VM cô lập với RansomWall bật
      3. Ghi feature vector vào CSV với header khớp FEATURE_ORDER
      4. Train lại: python train.py --real data.csv
      5. Đưa confusion matrix + precision/recall/F1 + feature_importance
         vào báo cáo (mục 6.3)
"""

import sys
import numpy as np
import joblib

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    confusion_matrix, classification_report,
    precision_recall_fscore_support, roc_auc_score,
)

# ── Vector 15 chiều — phải khớp với app.py và Features.h::ToJson ──────────
# 13 boolean F1–F13 (theo đúng thứ tự) + 2 đặc trưng tốc độ
FEATURE_ORDER = [
    # nhóm A — tĩnh
    "unsigned",            # F1
    "packed",              # F2
    "suspicious_strings",  # F3
    # nhóm C2 — trap
    "honey_modified",      # F4
    "crypto_api",          # F5
    "safe_mode_disable",   # F6
    "shadow_deleted",      # F7
    "registry_persist",    # F8
    # nhóm C3 — động
    "dir_enum",            # F9
    "high_io",             # F10
    "ext_changed",         # F11
    "fingerprint_mismatch",# F12
    "high_entropy",        # F13
    # đặc trưng tốc độ bổ sung (không phải Latch, không vào score)
    "io_rate",             # ops/giây trong cửa sổ 30s
    "mean_entropy_delta",  # ΔH trung bình
]

N_FEATURES = len(FEATURE_ORDER)  # = 15

rng = np.random.default_rng(42)


# ── Sinh dữ liệu tổng hợp ─────────────────────────────────────────────────

def gen_ransomware(n):
    """Feature vector đặc trưng của ransomware."""
    X = np.zeros((n, N_FEATURES))
    X[:, 0]  = rng.binomial(1, 0.90, n)   # unsigned       — hay không ký
    X[:, 1]  = rng.binomial(1, 0.75, n)   # packed         — thường bị pack
    X[:, 2]  = rng.binomial(1, 0.65, n)   # suspicious_strings
    X[:, 3]  = rng.binomial(1, 0.85, n)   # honey_modified — rất mạnh
    X[:, 4]  = rng.binomial(1, 0.80, n)   # crypto_api
    X[:, 5]  = rng.binomial(1, 0.45, n)   # safe_mode_disable
    X[:, 6]  = rng.binomial(1, 0.70, n)   # shadow_deleted — rất mạnh
    X[:, 7]  = rng.binomial(1, 0.40, n)   # registry_persist
    X[:, 8]  = rng.binomial(1, 0.90, n)   # dir_enum
    X[:, 9]  = rng.binomial(1, 0.95, n)   # high_io
    X[:, 10] = rng.binomial(1, 0.80, n)   # ext_changed
    X[:, 11] = rng.binomial(1, 0.85, n)   # fingerprint_mismatch
    X[:, 12] = rng.binomial(1, 0.88, n)   # high_entropy
    X[:, 13] = rng.gamma(4, 20, n)        # io_rate: cao (~80 ops/s)
    X[:, 14] = rng.normal(4.2, 1.2, n)    # mean_entropy_delta: lớn
    return X


def gen_benign(n):
    """
    Feature vector lành tính — cố ý làm khó: bao gồm 7-Zip,
    compiler, indexer, backup agent — những thứ dễ bị báo nhầm nhất.
    """
    X = np.zeros((n, N_FEATURES))
    X[:, 0]  = rng.binomial(1, 0.35, n)   # unsigned:  nhiều phần mềm OSS không ký
    X[:, 1]  = rng.binomial(1, 0.25, n)   # packed:    installer thường bị pack
    X[:, 2]  = rng.binomial(1, 0.03, n)
    X[:, 3]  = rng.binomial(1, 0.01, n)   # honey_modified: gần như không bao giờ
    X[:, 4]  = rng.binomial(1, 0.20, n)   # crypto_api: browser, VPN, backup tool
    X[:, 5]  = rng.binomial(1, 0.01, n)
    X[:, 6]  = rng.binomial(1, 0.01, n)
    X[:, 7]  = rng.binomial(1, 0.08, n)   # registry_persist: installer hợp lệ
    X[:, 8]  = rng.binomial(1, 0.45, n)   # dir_enum: indexer, backup agent
    X[:, 9]  = rng.binomial(1, 0.40, n)   # high_io:  7-Zip, compiler
    X[:, 10] = rng.binomial(1, 0.05, n)
    X[:, 11] = rng.binomial(1, 0.04, n)
    X[:, 12] = rng.binomial(1, 0.03, n)   # high_entropy: nén → ΔH nhỏ, không bật
    X[:, 13] = rng.gamma(2, 5, n)         # io_rate: thấp hơn nhiều
    X[:, 14] = rng.normal(0.1, 0.5, n)    # mean_entropy_delta: ~0 ← khác biệt lớn nhất
    return X


def load_real(csv_path):
    """Nạp dataset thật từ CSV. Header phải chứa các cột trong FEATURE_ORDER + 'label'."""
    import csv
    X, y = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            X.append([float(row.get(k, 0) or 0) for k in FEATURE_ORDER])
            y.append(int(row["label"]))
    return np.array(X), np.array(y)


# ── Train ──────────────────────────────────────────────────────────────────

def main():
    # Chọn nguồn dữ liệu
    if len(sys.argv) > 2 and sys.argv[1] == "--real":
        X, y = load_real(sys.argv[2])
        print(f"[train] Nap du lieu THAT tu {sys.argv[2]}: {len(y)} mau")
        synthetic = False
    else:
        n_mal, n_ben = 3000, 5000
        X = np.vstack([gen_ransomware(n_mal), gen_benign(n_ben)])
        y = np.hstack([np.ones(n_mal, dtype=int), np.zeros(n_ben, dtype=int)])
        print(f"[train] Sinh dataset TONG HOP: {n_mal} ransomware + {n_ben} benign")
        print("[train] !!! Dataset tong hop — KHONG co gia tri khoa hoc. Xem docstring. !!!")
        synthetic = True

    # Split
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # Model — Gradient Tree Boosting
    clf = GradientBoostingClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=4,
        subsample=0.8,
        min_samples_leaf=5,
        random_state=42,
    )
    print("[train] Dang train GradientBoostingClassifier (n=300, lr=0.05, depth=4)...")
    clf.fit(Xtr, ytr)

    # Đánh giá
    yp   = clf.predict(Xte)
    yprob = clf.predict_proba(Xte)[:, 1]
    cm   = confusion_matrix(yte, yp)
    p, r, f1, _ = precision_recall_fscore_support(yte, yp, average="binary")
    auc  = roc_auc_score(yte, yprob)
    cv   = cross_val_score(clf, X, y, cv=StratifiedKFold(5), scoring="f1")

    # Báo cáo
    lines = []
    lines.append("=" * 62)
    lines.append("RansomWall ML — Gradient Tree Boosting — Ket qua danh gia")
    lines.append("=" * 62)
    if synthetic:
        lines.append("")
        lines.append("!!! CANH BAO: train tren DATASET TONG HOP.")
        lines.append("!!! Cac so duoi day KHONG co gia tri khoa hoc.")
        lines.append("!!! Phai train lai tren mau that truoc khi bao ve.")
    lines.append("")
    lines.append(f"Model    : GradientBoostingClassifier")
    lines.append(f"Features : {N_FEATURES}  ({', '.join(FEATURE_ORDER)})")
    lines.append(f"Train    : {len(ytr)}  |  Test: {len(yte)}")
    lines.append("")
    lines.append("CONFUSION MATRIX")
    lines.append("                 Du doan BENIGN   Du doan MALWARE")
    lines.append(f"That BENIGN      {cm[0][0]:>13}   {cm[0][1]:>15}")
    lines.append(f"That MALWARE     {cm[1][0]:>13}   {cm[1][1]:>15}")
    lines.append("")
    lines.append(f"  False Positive (bao dong nham) : {cm[0][1]}")
    lines.append(f"  False Negative (BO SOT)        : {cm[1][0]}   <- ton kem nhat")
    lines.append("")
    lines.append(f"Precision     : {p:.4f}")
    lines.append(f"Recall        : {r:.4f}   <- uu tien chi so nay")
    lines.append(f"F1            : {f1:.4f}")
    lines.append(f"ROC-AUC       : {auc:.4f}")
    lines.append(f"CV F1 (5-fold): {cv.mean():.4f} +/- {cv.std():.4f}")
    lines.append("")
    lines.append(classification_report(yte, yp, target_names=["BENIGN", "MALWARE"]))
    lines.append("")
    lines.append("FEATURE IMPORTANCE (giam dan)")
    lines.append("-" * 62)
    order = np.argsort(clf.feature_importances_)[::-1]
    for i in order:
        bar = "#" * int(clf.feature_importances_[i] * 200)
        lines.append(f"  {FEATURE_ORDER[i]:<24} {clf.feature_importances_[i]:.4f}  {bar}")

    report = "\n".join(lines)
    print("\n" + report)

    with open("metrics.txt", "w", encoding="utf-8") as f:
        f.write(report)

    joblib.dump(clf, "model.pkl")
    print("\n-> Da luu model.pkl")
    print("-> Da luu metrics.txt  (dan vao muc 6.3 cua bao cao)")
    print("\nKhoi dong lai app.py de nap model moi.")


if __name__ == "__main__":
    main()