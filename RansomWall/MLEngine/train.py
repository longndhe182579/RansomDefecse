"""
train.py — RansomWall v4.0
13 features F1-F13 đúng theo bài báo:
  Shaukat & Ribeiro, "RansomWall: A layered defense system against
  cryptographic ransomware attacks using machine learning", COMSNETS 2018.

Chạy: python train.py
Xuất: model.pkl + ransomwall_dataset.csv + metrics.txt
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import KFold
from sklearn.metrics import classification_report, accuracy_score
import joblib

# ── 13 features F1–F13 — PHẢI khớp với FEATURE_ORDER trong app.py ───────────
FEATURE_NAMES = [
    'unsigned',             # F1  Static
    'packed',               # F2  Static
    'suspicious_strings',   # F3  Static
    'honey_modified',       # F4  Trap
    'crypto_api',           # F5  Trap
    'safe_mode_disable',    # F6  Trap
    'shadow_deleted',       # F7  Trap
    'registry_persist',     # F8  Trap
    'dir_enum',             # F9  Dynamic
    'high_io',              # F10 Dynamic
    'ext_changed',          # F11 Dynamic
    'fingerprint_mismatch', # F12 Dynamic
    'high_entropy',         # F13 Dynamic
]

NUM_RANSOMWARE = 574
NUM_BENIGN     = 442
np.random.seed(42)

def gen_ransomware():
    rtype = np.random.choice(['aggressive','stealthy','partial'], p=[0.5,0.3,0.2])
    if rtype == 'aggressive':
        return [
            np.random.choice([0,1], p=[0.05,0.95]),  # F1
            np.random.choice([0,1], p=[0.10,0.90]),  # F2
            np.random.choice([0,1], p=[0.10,0.90]),  # F3
            np.random.choice([0,1], p=[0.02,0.98]),  # F4 honey — rất mạnh
            np.random.choice([0,1], p=[0.20,0.80]),  # F5 crypto api
            np.random.choice([0,1], p=[0.50,0.50]),  # F6 safe mode
            np.random.choice([0,1], p=[0.05,0.95]),  # F7 shadow
            np.random.choice([0,1], p=[0.40,0.60]),  # F8 registry
            np.random.choice([0,1], p=[0.05,0.95]),  # F9
            np.random.choice([0,1], p=[0.05,0.95]),  # F10
            np.random.choice([0,1], p=[0.05,0.95]),  # F11
            np.random.choice([0,1], p=[0.05,0.95]),  # F12
            np.random.choice([0,1], p=[0.05,0.95]),  # F13
        ]
    elif rtype == 'stealthy':
        return [
            np.random.choice([0,1], p=[0.15,0.85]),
            np.random.choice([0,1], p=[0.30,0.70]),
            np.random.choice([0,1], p=[0.40,0.60]),
            np.random.choice([0,1], p=[0.10,0.90]),  # F4 vẫn chạm honey
            np.random.choice([0,1], p=[0.40,0.60]),
            np.random.choice([0,1], p=[0.70,0.30]),
            np.random.choice([0,1], p=[0.40,0.60]),
            np.random.choice([0,1], p=[0.60,0.40]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.15,0.85]),
        ]
    else:  # partial
        return [
            np.random.choice([0,1], p=[0.10,0.90]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.30,0.70]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.50,0.50]),
            np.random.choice([0,1], p=[0.80,0.20]),
            np.random.choice([0,1], p=[0.60,0.40]),
            np.random.choice([0,1], p=[0.70,0.30]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.50,0.50]),
            np.random.choice([0,1], p=[0.30,0.70]),
            np.random.choice([0,1], p=[0.30,0.70]),
        ]

def gen_benign():
    btype = np.random.choice(['trusted','unsigned_clean','noisy'], p=[0.5,0.3,0.2])
    if btype == 'trusted':
        return [
            np.random.choice([0,1], p=[0.95,0.05]),
            np.random.choice([0,1], p=[0.98,0.02]),
            np.random.choice([0,1], p=[0.99,0.01]),
            0,  # F4 honey — KHÔNG BAO GIỜ
            np.random.choice([0,1], p=[0.80,0.20]),  # F5 browser/VPN ok
            0,  # F6
            0,  # F7
            np.random.choice([0,1], p=[0.92,0.08]),  # F8 installer ok
            np.random.choice([0,1], p=[0.70,0.30]),
            np.random.choice([0,1], p=[0.80,0.20]),
            0,  # F11
            np.random.choice([0,1], p=[0.90,0.10]),
            np.random.choice([0,1], p=[0.98,0.02]),
        ]
    elif btype == 'unsigned_clean':
        return [
            np.random.choice([0,1], p=[0.20,0.80]),
            np.random.choice([0,1], p=[0.60,0.40]),
            np.random.choice([0,1], p=[0.90,0.10]),
            0,  # F4
            np.random.choice([0,1], p=[0.70,0.30]),
            0, 0,
            np.random.choice([0,1], p=[0.85,0.15]),
            np.random.choice([0,1], p=[0.50,0.50]),
            np.random.choice([0,1], p=[0.60,0.40]),
            0,
            np.random.choice([0,1], p=[0.70,0.30]),
            np.random.choice([0,1], p=[0.85,0.15]),
        ]
    else:  # noisy — antivirus, indexer
        return [
            np.random.choice([0,1], p=[0.80,0.20]),
            np.random.choice([0,1], p=[0.95,0.05]),
            np.random.choice([0,1], p=[0.95,0.05]),
            0,  # F4 honey — KHÔNG BAO GIỜ
            np.random.choice([0,1], p=[0.60,0.40]),
            0, 0,
            np.random.choice([0,1], p=[0.90,0.10]),
            np.random.choice([0,1], p=[0.20,0.80]),  # F9 dir_enum cao
            np.random.choice([0,1], p=[0.20,0.80]),  # F10 high_io cao
            0,  # F11 ext_changed — KHÔNG
            np.random.choice([0,1], p=[0.60,0.40]),
            np.random.choice([0,1], p=[0.90,0.10]),
        ]

# ── Sinh dataset ──────────────────────────────────────────────────────────────
print("=" * 65)
print("RansomWall v4.0 — GradientBoostingClassifier — 13 features")
print("Tham khao: Shaukat & Ribeiro, COMSNETS 2018")
print("=" * 65)

X_list, y_list = [], []
for _ in range(NUM_RANSOMWARE):
    X_list.append(gen_ransomware()); y_list.append(1)
for _ in range(NUM_BENIGN):
    X_list.append(gen_benign());     y_list.append(0)

df = pd.DataFrame(X_list, columns=FEATURE_NAMES)
df['label'] = y_list
df.to_csv('ransomwall_dataset.csv', index=False)
print(f"[+] Dataset: {NUM_RANSOMWARE} ransomware + {NUM_BENIGN} benign")

X = df[FEATURE_NAMES].values
y = df['label'].values

# ── 12-fold cross validation ──────────────────────────────────────────────────
print("\n[+] 12-Fold Cross Validation...")
kf   = KFold(n_splits=12, shuffle=True, random_state=42)
accs = []
for fold, (tr, te) in enumerate(kf.split(X, y), 1):
    m = GradientBoostingClassifier(
        n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
    m.fit(X[tr], y[tr])
    acc = accuracy_score(y[te], m.predict(X[te]))
    accs.append(acc)
    print(f"   Fold {fold:2d}/12 — {acc*100:.2f}%")
print(f"\n==> Accuracy trung binh: {np.mean(accs)*100:.2f}%")

# ── Train final model ─────────────────────────────────────────────────────────
print("\n[+] Train model final...")
model = GradientBoostingClassifier(
    n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42)
model.fit(X, y)
print(classification_report(y, model.predict(X), target_names=['Benign','Ransomware']))

# ── Test case từ log WannaCry thực tế ────────────────────────────────────────
print("[+] Test case thuc te (vector tu log WannaCry):")
test_cases = [
    ([1,1,1,0,0,0,0,0,1,1,0,1,1], "WannaCry score=6 (lan 1)"),
    ([1,1,1,0,0,0,0,0,1,1,0,1,1], "WannaCry score=7 (lan 2)"),
    ([1,1,1,1,0,0,1,0,1,1,1,1,1], "WannaCry aggressive (honey+shadow)"),
    ([1,0,0,0,0,0,0,0,1,1,0,0,0], "7-Zip/indexer (BENIGN)"),
    ([0,0,0,0,1,0,0,0,0,1,0,0,0], "Browser/VPN (BENIGN)"),
]
for feat, label in test_cases:
    prob = model.predict_proba([feat])[0][1]
    dec  = "MALWARE" if prob >= 0.5 else "BENIGN"
    print(f"   prob={prob:.3f} -> {dec:7s} | {label}")

joblib.dump(model, 'model.pkl')
print("\n[SUCCESS] Da luu model.pkl (13 features, dung bai bao)")