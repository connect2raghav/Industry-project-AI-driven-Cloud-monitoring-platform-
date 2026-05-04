"""
ML Model Training Script — 3 Specialist Models on 3 Different Datasets
=======================================================================

Model → Dataset → Specialises In
─────────────────────────────────────────────────────────────────────
IForest  → NSL-KDD      → Brute force, privilege escalation, port scan, R2L/U2R
KNN      → CICIDS-2017  → DDoS, web attacks, botnet, infiltration, lateral movement
HBOS     → UNSW-NB15    → Malware, reconnaissance, backdoors, shellcode, worms

All 3 datasets are downloaded automatically.
All 3 models are mapped to the same 3 features:
  level              (Wazuh severity 1–15)
  bytes_transferred  (total data volume)
  failed_attempts    (login/connection failures)

Run once:
  cd backend
  python train_model.py

Saved to backend/models/:
  iforest.pkl          ← NSL-KDD specialist
  knn.pkl              ← CICIDS-2017 specialist
  hbos.pkl             ← UNSW-NB15 specialist
  scaler_iforest.pkl
  scaler_knn.pkl
  scaler_hbos.pkl
  training_meta.json
"""

import os
import json
import urllib.request
import zipfile
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR   = os.path.join(BASE_DIR, "data")
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATA_DIR,   exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
# DATASET 1 — NSL-KDD  (IForest specialist)
# ══════════════════════════════════════════════════════════════════════════════

NSL_TRAIN_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
NSL_TEST_URL   = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
NSL_TRAIN_PATH = os.path.join(DATA_DIR, "KDDTrain+.txt")
NSL_TEST_PATH  = os.path.join(DATA_DIR, "KDDTest+.txt")

NSL_COLUMNS = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty"
]

NSL_ATTACK_CATEGORY = {
    "normal":"normal",
    "back":"dos","land":"dos","neptune":"dos","pod":"dos",
    "smurf":"dos","teardrop":"dos","mailbomb":"dos",
    "apache2":"dos","processtable":"dos","udpstorm":"dos",
    "ipsweep":"probe","nmap":"probe","portsweep":"probe",
    "satan":"probe","mscan":"probe","saint":"probe",
    "ftp_write":"r2l","guess_passwd":"r2l","imap":"r2l",
    "multihop":"r2l","phf":"r2l","spy":"r2l","warezclient":"r2l",
    "warezmaster":"r2l","sendmail":"r2l","named":"r2l",
    "snmpgetattack":"r2l","snmpguess":"r2l","xlock":"r2l",
    "xsnoop":"r2l","httptunnel":"r2l",
    "buffer_overflow":"u2r","loadmodule":"u2r","perl":"u2r",
    "rootkit":"u2r","ps":"u2r","sqlattack":"u2r","xterm":"u2r",
}

NSL_LEVEL_MAP = {
    "normal":2, "dos":13, "probe":8, "r2l":10, "u2r":14
}


def load_nslkdd():
    for url, path in [(NSL_TRAIN_URL, NSL_TRAIN_PATH), (NSL_TEST_URL, NSL_TEST_PATH)]:
        if not os.path.exists(path):
            print(f"  Downloading {os.path.basename(path)} ...")
            urllib.request.urlretrieve(url, path)

    def _parse(path):
        df = pd.read_csv(path, header=None, names=NSL_COLUMNS)
        df["label"] = df["label"].str.strip().str.lower().str.rstrip(".")
        df["cat"]   = df["label"].map(lambda x: NSL_ATTACK_CATEGORY.get(x, "probe"))
        df["level"] = df["cat"].map(NSL_LEVEL_MAP).fillna(8).astype(int)
        df["bytes_transferred"] = (
            pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0) +
            pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0)
        )
        df["failed_attempts"] = (
            pd.to_numeric(df["num_failed_logins"], errors="coerce").fillna(0) +
            pd.to_numeric(df["rerror_rate"],       errors="coerce").fillna(0) * 100 +
            pd.to_numeric(df["serror_rate"],       errors="coerce").fillna(0) * 50
        ).astype(int)
        df["is_anomaly"] = (df["cat"] != "normal").astype(int)
        return df[["level","bytes_transferred","failed_attempts","is_anomaly","cat"]]

    train = _parse(NSL_TRAIN_PATH)
    test  = _parse(NSL_TEST_PATH)
    print(f"  NSL-KDD  — train: {len(train):,}  test: {len(test):,}  "
          f"attack ratio: {train['is_anomaly'].mean():.2%}")
    return train, test


# ══════════════════════════════════════════════════════════════════════════════
# DATASET 2 — CICIDS-2017  (KNN specialist)
# Uses the Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv subset
# which is small enough to download quickly (~24 MB)
# ══════════════════════════════════════════════════════════════════════════════

CICIDS_URL  = (
    "https://raw.githubusercontent.com/CanadianInstituteForCybersecurity/"
    "CIC-IDS-2017/master/GeneratedLabelledFlows/TrafficLabels/"
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)
CICIDS_PATH = os.path.join(DATA_DIR, "cicids_ddos.csv")

# Fallback mirror (GitHub raw sometimes rate-limits)
CICIDS_FALLBACK_URL = (
    "https://raw.githubusercontent.com/wesleyit/ml_ids_cicids2017/"
    "main/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)


def load_cicids():
    if not os.path.exists(CICIDS_PATH):
        print(f"  Downloading CICIDS-2017 DDoS subset ...")
        try:
            urllib.request.urlretrieve(CICIDS_URL, CICIDS_PATH)
        except Exception:
            try:
                urllib.request.urlretrieve(CICIDS_FALLBACK_URL, CICIDS_PATH)
            except Exception as e:
                print(f"  CICIDS download failed: {e}")
                print("  Generating synthetic CICIDS-style data instead ...")
                return _synthetic_cicids()

    try:
        df = pd.read_csv(CICIDS_PATH, low_memory=False)
    except Exception as e:
        print(f"  CICIDS parse failed: {e} — using synthetic data")
        return _synthetic_cicids()

    # Strip column name whitespace
    df.columns = df.columns.str.strip()

    # Label column varies — find it
    label_col = next((c for c in df.columns if "label" in c.lower()), None)
    if label_col is None:
        return _synthetic_cicids()

    df["is_anomaly"] = (df[label_col].str.strip().str.upper() != "BENIGN").astype(int)

    # Map to our 3 features
    # Total bytes = Fwd + Bwd packet lengths
    fwd_col = next((c for c in df.columns if "fwd" in c.lower() and "byte" in c.lower()), None)
    bwd_col = next((c for c in df.columns if "bwd" in c.lower() and "byte" in c.lower()), None)
    pkt_col = next((c for c in df.columns if "packet" in c.lower() and "length" in c.lower() and "sum" in c.lower()), None)

    if fwd_col and bwd_col:
        df["bytes_transferred"] = (
            pd.to_numeric(df[fwd_col], errors="coerce").fillna(0) +
            pd.to_numeric(df[bwd_col], errors="coerce").fillna(0)
        )
    elif pkt_col:
        df["bytes_transferred"] = pd.to_numeric(df[pkt_col], errors="coerce").fillna(0)
    else:
        df["bytes_transferred"] = 0.0

    # Failed attempts ≈ RST flags + FIN flags (connection resets indicate failures)
    rst_col = next((c for c in df.columns if "rst" in c.lower() and "flag" in c.lower()), None)
    df["failed_attempts"] = pd.to_numeric(df[rst_col], errors="coerce").fillna(0).astype(int) if rst_col else 0

    # Level: DDoS/attack = 13, benign = 2
    df["level"] = df["is_anomaly"].map({1: 13, 0: 2})

    df = df[["level","bytes_transferred","failed_attempts","is_anomaly"]].dropna()
    df = df.replace([np.inf, -np.inf], 0)

    # Balance: keep all attacks + equal normal
    attacks = df[df["is_anomaly"] == 1]
    normal  = df[df["is_anomaly"] == 0].sample(
        min(len(attacks) * 3, len(df[df["is_anomaly"] == 0])), random_state=42
    )
    df = pd.concat([attacks, normal]).sample(frac=1, random_state=42).reset_index(drop=True)

    # Train/test split 80/20
    split = int(len(df) * 0.8)
    train, test = df.iloc[:split], df.iloc[split:]

    print(f"  CICIDS-2017 — train: {len(train):,}  test: {len(test):,}  "
          f"attack ratio: {train['is_anomaly'].mean():.2%}")
    return train, test


def _synthetic_cicids():
    """
    Generate synthetic CICIDS-style data when download fails.
    DDoS pattern: very high bytes_transferred, moderate level.
    """
    np.random.seed(42)
    n_normal  = 40000
    n_attack  = 15000

    normal = pd.DataFrame({
        "level":             np.random.randint(1, 5, n_normal),
        "bytes_transferred": np.random.exponential(5000, n_normal),
        "failed_attempts":   np.zeros(n_normal, dtype=int),
        "is_anomaly":        np.zeros(n_normal, dtype=int),
    })
    # DDoS: massive bytes, moderate-high level, near-zero failed_attempts
    # Botnet: moderate bytes, high level, some failed_attempts
    # Web attack: low bytes, high level, many failed_attempts
    ddos = pd.DataFrame({
        "level":             np.random.randint(11, 14, n_attack // 3),
        "bytes_transferred": np.random.uniform(10_000_000, 500_000_000, n_attack // 3),
        "failed_attempts":   np.random.randint(0, 3, n_attack // 3),
        "is_anomaly":        np.ones(n_attack // 3, dtype=int),
    })
    botnet = pd.DataFrame({
        "level":             np.random.randint(10, 13, n_attack // 3),
        "bytes_transferred": np.random.uniform(50_000, 2_000_000, n_attack // 3),
        "failed_attempts":   np.random.randint(5, 30, n_attack // 3),
        "is_anomaly":        np.ones(n_attack // 3, dtype=int),
    })
    web = pd.DataFrame({
        "level":             np.random.randint(9, 13, n_attack // 3),
        "bytes_transferred": np.random.uniform(1000, 50_000, n_attack // 3),
        "failed_attempts":   np.random.randint(20, 200, n_attack // 3),
        "is_anomaly":        np.ones(n_attack // 3, dtype=int),
    })
    df    = pd.concat([normal, ddos, botnet, web]).sample(frac=1, random_state=42).reset_index(drop=True)
    split = int(len(df) * 0.8)
    train, test = df.iloc[:split], df.iloc[split:]
    print(f"  CICIDS-2017 (synthetic) — train: {len(train):,}  test: {len(test):,}")
    return train, test


# ══════════════════════════════════════════════════════════════════════════════
# DATASET 3 — UNSW-NB15  (HBOS specialist)
# ══════════════════════════════════════════════════════════════════════════════

UNSW_TRAIN_URL  = "https://raw.githubusercontent.com/AbertayMachineLearningGroup/UNSW-NB15-PYTHON/master/UNSW_NB15_training-set.csv"
UNSW_TEST_URL   = "https://raw.githubusercontent.com/AbertayMachineLearningGroup/UNSW-NB15-PYTHON/master/UNSW_NB15_testing-set.csv"
UNSW_TRAIN_PATH = os.path.join(DATA_DIR, "unsw_train.csv")
UNSW_TEST_PATH  = os.path.join(DATA_DIR, "unsw_test.csv")

UNSW_ATTACK_LEVEL = {
    "normal":       2,
    "generic":      9,
    "exploits":     12,
    "fuzzers":      8,
    "dos":          13,
    "reconnaissance": 8,
    "analysis":     7,
    "backdoor":     14,
    "shellcode":    15,
    "worms":        15,
}


def load_unsw():
    for url, path in [(UNSW_TRAIN_URL, UNSW_TRAIN_PATH), (UNSW_TEST_URL, UNSW_TEST_PATH)]:
        if not os.path.exists(path):
            print(f"  Downloading {os.path.basename(path)} ...")
            try:
                urllib.request.urlretrieve(url, path)
            except Exception as e:
                print(f"  UNSW-NB15 download failed: {e}")
                print("  Generating synthetic UNSW-NB15-style data instead ...")
                return _synthetic_unsw()

    try:
        train_df = pd.read_csv(UNSW_TRAIN_PATH, low_memory=False)
        test_df  = pd.read_csv(UNSW_TEST_PATH,  low_memory=False)
    except Exception as e:
        print(f"  UNSW parse failed: {e} — using synthetic data")
        return _synthetic_unsw()

    def _parse_unsw(df):
        df.columns = df.columns.str.strip().str.lower()

        # Label column
        label_col = next((c for c in df.columns if c in ("label","attack_cat","class")), None)
        if label_col is None:
            return None

        # is_anomaly
        if df[label_col].dtype == object:
            df["is_anomaly"] = (df[label_col].str.strip().str.lower() != "normal").astype(int)
            df["cat"]        = df[label_col].str.strip().str.lower()
        else:
            df["is_anomaly"] = df[label_col].astype(int)
            df["cat"]        = "unknown"

        # level from attack category
        cat_col = next((c for c in df.columns if "attack_cat" in c), None)
        if cat_col:
            df["level"] = df[cat_col].str.strip().str.lower().map(
                lambda x: UNSW_ATTACK_LEVEL.get(x, 8)
            )
        else:
            df["level"] = df["is_anomaly"].map({1: 10, 0: 2})

        # bytes_transferred
        sbytes = next((c for c in df.columns if c in ("sbytes","src_bytes","spkts")), None)
        dbytes = next((c for c in df.columns if c in ("dbytes","dst_bytes","dpkts")), None)
        if sbytes and dbytes:
            df["bytes_transferred"] = (
                pd.to_numeric(df[sbytes], errors="coerce").fillna(0) +
                pd.to_numeric(df[dbytes], errors="coerce").fillna(0)
            )
        else:
            df["bytes_transferred"] = 0.0

        # failed_attempts — connection state errors
        state_col = next((c for c in df.columns if "state" in c), None)
        if state_col:
            df["failed_attempts"] = (
                df[state_col].str.strip().str.upper().isin(["REJ","RSTO","RSTOS0","RSTR"])
            ).astype(int) * 10
        else:
            df["failed_attempts"] = 0

        return df[["level","bytes_transferred","failed_attempts","is_anomaly"]].dropna()

    train = _parse_unsw(train_df)
    test  = _parse_unsw(test_df)

    if train is None or test is None:
        return _synthetic_unsw()

    train = train.replace([np.inf, -np.inf], 0)
    test  = test.replace([np.inf, -np.inf], 0)

    print(f"  UNSW-NB15 — train: {len(train):,}  test: {len(test):,}  "
          f"attack ratio: {train['is_anomaly'].mean():.2%}")
    return train, test


def _synthetic_unsw():
    """
    Generate synthetic UNSW-NB15-style data when download fails.
    Malware/backdoor pattern: low bytes, high level, some failed attempts.
    """
    np.random.seed(123)
    n_normal = 50000
    n_attack = 20000

    normal = pd.DataFrame({
        "level":             np.random.randint(1, 4, n_normal),
        "bytes_transferred": np.random.exponential(3000, n_normal),
        "failed_attempts":   np.zeros(n_normal, dtype=int),
        "is_anomaly":        np.zeros(n_normal, dtype=int),
    })
    # Malware/backdoor: moderate bytes, very high level, some failures
    attack = pd.DataFrame({
        "level":             np.random.randint(12, 16, n_attack),
        "bytes_transferred": np.random.exponential(8000, n_attack),
        "failed_attempts":   np.random.randint(5, 50, n_attack),
        "is_anomaly":        np.ones(n_attack, dtype=int),
    })
    df    = pd.concat([normal, attack]).sample(frac=1, random_state=42).reset_index(drop=True)
    split = int(len(df) * 0.8)
    train, test = df.iloc[:split], df.iloc[split:]
    print(f"  UNSW-NB15 (synthetic) — train: {len(train):,}  test: {len(test):,}")
    return train, test


# ══════════════════════════════════════════════════════════════════════════════
# TRAINING
# ══════════════════════════════════════════════════════════════════════════════

FEATURES = ["level", "bytes_transferred", "failed_attempts"]


def _clip_and_scale(train_X, test_X, name):
    """Clip bytes at 99th percentile then MinMaxScale."""
    p99 = float(np.percentile(train_X[:, 1], 99))
    train_X = train_X.copy()
    test_X  = test_X.copy()
    train_X[:, 1] = np.clip(train_X[:, 1], 0, p99)
    test_X[:, 1]  = np.clip(test_X[:, 1],  0, p99)
    scaler = MinMaxScaler()
    train_scaled = scaler.fit_transform(train_X)
    test_scaled  = scaler.transform(test_X)
    scaler_path  = os.path.join(MODELS_DIR, f"scaler_{name}.pkl")
    joblib.dump(scaler, scaler_path)
    return train_scaled, test_scaled, scaler, p99


def _evaluate(model, X_test, y_test):
    probs       = model.predict_proba(X_test)[:, 1]
    predictions = (probs > 0.5).astype(int)
    tp = int(np.sum((predictions == 1) & (y_test == 1)))
    fp = int(np.sum((predictions == 1) & (y_test == 0)))
    fn = int(np.sum((predictions == 0) & (y_test == 1)))
    tn = int(np.sum((predictions == 0) & (y_test == 0)))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / len(y_test)
    return {
        "accuracy":  round(accuracy  * 100, 2),
        "precision": round(precision * 100, 2),
        "recall":    round(recall    * 100, 2),
        "f1_score":  round(f1        * 100, 2),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
    }


def train_specialist(name, model, train_df, test_df, dataset_name, specialises_in):
    print(f"\n--- {name} on {dataset_name} ---")
    X_train = train_df[FEATURES].values.astype(float)
    X_test  = test_df[FEATURES].values.astype(float)
    y_test  = test_df["is_anomaly"].values

    contamination = float(train_df["is_anomaly"].mean())
    contamination = max(0.01, min(0.49, contamination))
    model.contamination = contamination

    X_train_s, X_test_s, scaler, p99 = _clip_and_scale(X_train, X_test, name)

    print(f"  Training on {len(X_train_s):,} samples  "
          f"(contamination={contamination:.3f}) ...")
    model.fit(X_train_s)

    metrics = _evaluate(model, X_test_s, y_test)
    print(f"  Accuracy : {metrics['accuracy']}%")
    print(f"  Precision: {metrics['precision']}%")
    print(f"  Recall   : {metrics['recall']}%")
    print(f"  F1 Score : {metrics['f1_score']}%")

    model_path = os.path.join(MODELS_DIR, f"{name}.pkl")
    joblib.dump(model, model_path)
    print(f"  Saved → {model_path}")

    return {
        "model":          name,
        "dataset":        dataset_name,
        "specialises_in": specialises_in,
        "train_samples":  len(X_train_s),
        "contamination":  contamination,
        "p99_bytes_clip": p99,
        "performance":    metrics,
    }


def train():
    print("\n=== Ram Antivirus — Specialist ML Model Training ===\n")
    print("Loading datasets ...\n")

    # Load all 3 datasets
    nsl_train,   nsl_test   = load_nslkdd()
    cicids_train, cicids_test = load_cicids()
    unsw_train,  unsw_test  = load_unsw()

    results = {}

    # ── Model 1: Isolation Forest on NSL-KDD ─────────────────────────────────
    results["iforest"] = train_specialist(
        name          = "iforest",
        model         = IForest(n_estimators=200, random_state=42, n_jobs=-1),
        train_df      = nsl_train,
        test_df       = nsl_test,
        dataset_name  = "NSL-KDD",
        specialises_in= "brute_force, privilege_escalation, port_scan, r2l, u2r"
    )

    # ── Model 2: KNN on CICIDS-2017 ───────────────────────────────────────────
    # Subsample to max 30k rows so KNN stays fast
    cicids_train_sub = cicids_train.sample(
        min(30000, len(cicids_train)), random_state=42
    ).reset_index(drop=True)
    cicids_test_sub  = cicids_test.sample(
        min(8000, len(cicids_test)), random_state=42
    ).reset_index(drop=True)

    results["knn"] = train_specialist(
        name          = "knn",
        model         = KNN(n_neighbors=5, n_jobs=-1),
        train_df      = cicids_train_sub,
        test_df       = cicids_test_sub,
        dataset_name  = "CICIDS-2017",
        specialises_in= "ddos, web_attacks, botnet, infiltration, lateral_movement"
    )

    # ── Model 3: HBOS on UNSW-NB15 ───────────────────────────────────────────
    results["hbos"] = train_specialist(
        name          = "hbos",
        model         = HBOS(n_bins=30),
        train_df      = unsw_train,
        test_df       = unsw_test,
        dataset_name  = "UNSW-NB15",
        specialises_in= "malware, reconnaissance, backdoor, shellcode, worms"
    )

    # ── Save metadata ─────────────────────────────────────────────────────────
    meta = {
        "training_mode": "specialist",
        "features":      FEATURES,
        "models":        results,
        "scoring_strategy": (
            "Each event is scored by all 3 specialist models. "
            "Final score = max(iforest, knn, hbos). "
            "Detected_by = model with highest score."
        ),
    }
    meta_path = os.path.join(MODELS_DIR, "training_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\n  Metadata saved → {meta_path}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n=== Training Summary ===\n")
    print(f"  {'Model':<12} {'Dataset':<15} {'F1':>6}  Specialises In")
    print(f"  {'─'*12} {'─'*15} {'─'*6}  {'─'*40}")
    for k, v in results.items():
        f1 = v["performance"]["f1_score"]
        print(f"  {k:<12} {v['dataset']:<15} {f1:>5}%  {v['specialises_in']}")

    print("\n=== All models saved to backend/models/ ===\n")
    return meta


if __name__ == "__main__":
    train()
