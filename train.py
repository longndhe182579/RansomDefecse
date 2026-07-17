"""
train.py — Train Random Forest cho RansomWall

Chạy:  python train.py
Xuất:  model.pkl  +  metrics.txt  +  feature_importance.txt

CẢNH BÁO QUAN TRỌNG CHO ĐỒ ÁN:
    Script này sinh DATASET TỔNG HỢP để pipeline chạy được ngay.
    Model train trên dữ liệu tổng hợp KHÔNG có giá trị khoa học.

    Để bảo vệ đồ án bạn PHẢI:
      1. Thu thập mẫu ransomware thật (VirusShare, MalwareBazaar, theZoo)
         và mẫu benign thật (phần mềm phổ biến trên máy)
      2. Chạy từng mẫu trong VM cô lập với RansomWall bật
      3. Ghi feature vector thật vào CSV  (dùng --collect ở dưới)
      4. Train lại trên CSV đó
      5. Đưa confusion matrix + precision/recall/F1 + feature importance
         vào báo cáo (mục 6.3)

    Dùng --real data.csv để train trên dữ liệu thật.
"""

import sys
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (confusion_matrix, classification_report,
                             precision_recall_fscore_support, roc_auc_score)

FEATURE_ORDER = [
    "unsigned", "packed", "suspicious_strings",
    "honey_modified", "crypto_api", "safe_mode_disable",
    "shadow_deleted", "registry_persist",
    "dir_enum", "high_io", "ext_changed",
    "fingerprint_mismatch", "high_entropy",
    "io_rate", "rename_rate", "affected_ext_count", "mean_entropy_delta",
]

rng = np.random.default_rng(42)


def gen_ransomware(n):
    """Sinh feature vector giống ransomware."""
    X = np.zeros((n, len(FEATURE_ORDER)))
    X[:, 0] = rng.binomial(1, 0.90, n)   # unsigned
    X[:, 1] = rng.binomial(1, 0.75, n)   # packed
    X[:, 2] = rng.binomial(1, 0.65, n)   # suspicious_strings
    X[:, 3] = rng.binomial(1, 0.85, n)   # honey_modified  <- rat manh
    X[:, 4] = rng.binomial(1, 0.80, n)   # crypto_api
    X[:, 5] = rng.binomial(1, 0.45, n)   # safe_mode_disable
    X[:, 6] = rng.binomial(1, 0.70, n)   # shadow_deleted  <- rat manh
    X[:, 7] = rng.binomial(1, 0.40, n)   # registry_persist
    X[:, 8] = rng.binomial(1, 0.90, n)   # dir_enum
    X[:, 9] = rng.binomial(1, 0.95, n)   # high_io
    X[:, 10] = rng.binomial(1, 0.80, n)  # ext_changed
    X[:, 11] = rng.binomial(1, 0.85, n)  # fingerprint_mismatch
    X[:, 12] = rng.binomial(1, 0.88, n)  # high_entropy (dH > 2.0)
    X[:, 13] = rng.gamma(4, 20, n)       # io_rate: cao
    X[:, 14] = rng.gamma(3, 8, n)        # rename_rate: cao
    X[:, 15] = rng.integers(3, 15, n)    # affected_ext_count: nhieu loai
    X[:, 16] = rng.normal(4.2, 1.2, n)   # mean_entropy_delta: LON
    return X


def gen_benign(n):
    """
    Sinh feature vector lanh tinh — CO CHU DICH lam kho:
    bao gom 7-Zip, compiler, indexer, backup agent... la nhung thu
    de bi bao dong nham nhat.
    """
    X = np.zeros((n, len(FEATURE_ORDER)))
    X[:, 0] = rng.binomial(1, 0.35, n)   # unsigned: RAT NHIEU phan mem lanh tinh unsigned
    X[:, 1] = rng.binomial(1, 0.25, n)   # packed:   installer thuong bi pack
    X[:, 2] = rng.binomial(1, 0.03, n)
    X[:, 3] = rng.binomial(1, 0.01, n)   # honey_modified: gan nhu khong bao gio
    X[:, 4] = rng.binomial(1, 0.20, n)   # crypto_api: browser, VPN, backup tool co dung
    X[:, 5] = rng.binomial(1, 0.01, n)
    X[:, 6] = rng.binomial(1, 0.01, n)
    X[:, 7] = rng.binomial(1, 0.08, n)   # registry_persist: installer hop le co lam
    X[:, 8] = rng.binomial(1, 0.45, n)   # dir_enum: indexer, backup agent
    X[:, 9] = rng.binomial(1, 0.40, n)   # high_io:  7-Zip, compiler
    X[:, 10] = rng.binomial(1, 0.05, n)
    X[:, 11] = rng.binomial(1, 0.04, n)
    X[:, 12] = rng.binomial(1, 0.03, n)  # high_entropy: nho dH nen 7-Zip KHONG bat
    X[:, 13] = rng.gamma(2, 5, n)        # io_rate: thap hon
    X[:, 14] = rng.gamma(1, 1, n)        # rename_rate: rat thap
    X[:, 15] = rng.integers(1, 4, n)     # affected_ext_count: it loai
    X[:, 16] = rng.normal(0.1, 0.5, n)   # mean_entropy_delta: ~0  <- KHAC BIET LON NHAT
    return X


def load_real(csv_path):
    import csv
    X, y = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            X.append([float(row.get(k, 0) or 0) for k in FEATURE_ORDER])
            y.append(int(row["label"]))
    return np.array(X), np.array(y)


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--real":
        X, y = load_real(sys.argv[2])
        print(f"Nap du lieu THAT tu {sys.argv[2]}: {len(y)} mau")
        synthetic = False
    else:
        n_mal, n_ben = 3000, 5000
        X = np.vstack([gen_ransomware(n_mal), gen_benign(n_ben)])
        y = np.hstack([np.ones(n_mal), np.zeros(n_ben)])
        print(f"Sinh dataset TONG HOP: {n_mal} ransomware + {n_ben} benign")
        print("!!! Dataset tong hop — KHONG co gia tri khoa hoc. Xem docstring. !!!")
        synthetic = True

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25,
                                          random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=3,
        class_weight={0: 1.0, 1: 2.0},   # UU TIEN RECALL: bo sot ransomware ton hon
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(Xtr, ytr)

    yp = clf.predict(Xte)
    yprob = clf.predict_proba(Xte)[:, 1]

    cm = confusion_matrix(yte, yp)
    p, r, f1, _ = precision_recall_fscore_support(yte, yp, average="binary")
    auc = roc_auc_score(yte, yprob)
    cv = cross_val_score(clf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42),
                         scoring="f1")

    lines = []
    lines.append("=" * 62)
    lines.append("RansomWall ML — Ket qua danh gia")
    lines.append("=" * 62)
    if synthetic:
        lines.append("")
        lines.append("!!! CANH BAO: train tren DATASET TONG HOP.")
        lines.append("!!! Cac so duoi day KHONG co gia tri khoa hoc.")
        lines.append("!!! Phai train lai tren mau that truoc khi bao ve.")
    lines.append("")
    lines.append("CONFUSION MATRIX")
    lines.append("                 Du doan BENIGN   Du doan MALWARE")
    lines.append(f"That BENIGN      {cm[0][0]:>13}   {cm[0][1]:>15}")
    lines.append(f"That MALWARE     {cm[1][0]:>13}   {cm[1][1]:>15}")
    lines.append("")
    lines.append(f"  False Positive (bao dong nham) : {cm[0][1]}")
    lines.append(f"  False Negative (BO SOT)        : {cm[1][0]}   <- ton kem nhat")
    lines.append("")
    lines.append(f"Precision : {p:.4f}")
    lines.append(f"Recall    : {r:.4f}   <- uu tien chi so nay")
    lines.append(f"F1        : {f1:.4f}")
    lines.append(f"ROC-AUC   : {auc:.4f}")
    lines.append(f"CV F1 (5-fold): {cv.mean():.4f} +/- {cv.std():.4f}")
    lines.append("")
    lines.append(classification_report(yte, yp, target_names=["BENIGN", "MALWARE"]))

    lines.append("")
    lines.append("FEATURE IMPORTANCE")
    lines.append("-" * 62)
    order = np.argsort(clf.feature_importances_)[::-1]
    for i in order:
        bar = "#" * int(clf.feature_importances_[i] * 200)
        lines.append(f"  {FEATURE_ORDER[i]:<22} {clf.feature_importances_[i]:.4f}  {bar}")

    out = "\n".join(lines)
    print("\n" + out)
    with open("metrics.txt", "w", encoding="utf-8") as f:
        f.write(out)

    joblib.dump(clf, "model.pkl")
    print("\n-> Da luu model.pkl")
    print("-> Da luu metrics.txt  (dan vao muc 6.3 cua bao cao)")
    print("\nKhoi dong lai app.py de nap model moi.")


if __name__ == "__main__":
    main()
