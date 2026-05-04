"""
ML Engine — 3 Specialist PyOD Models
=====================================
Each model is trained on a different dataset and specialises in
a different attack category:

  iforest  (NSL-KDD)      → brute_force, privilege_escalation, port_scan
  knn      (CICIDS-2017)  → ddos, web_attacks, botnet, lateral_movement
  hbos     (UNSW-NB15)    → malware, reconnaissance, backdoor, shellcode

Scoring strategy:
  Every event is scored by all 3 models.
  Final score  = max(iforest_score, knn_score, hbos_score)
  Detected_by  = whichever model gave the highest score

If no saved models exist, falls back to per-request IForest fitting
and prints a warning telling you to run train_model.py.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import List, Dict

from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS

FEATURES   = ["level", "bytes_transferred", "failed_attempts"]
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
META_PATH  = os.path.join(MODELS_DIR, "training_meta.json")

MODEL_DISPLAY = {
    "iforest": "Isolation Forest (NSL-KDD)",
    "knn":     "KNN (CICIDS-2017)",
    "hbos":    "HBOS (UNSW-NB15)",
}


# ── Load saved models on module import ───────────────────────────────────────

def _load():
    """
    Load all 3 specialist models + their scalers from disk.
    Returns (models, scalers, meta) or (None, None, None).
    """
    if not os.path.exists(MODELS_DIR):
        return None, None, None

    models  = {}
    scalers = {}

    for name in ["iforest", "knn", "hbos"]:
        m_path = os.path.join(MODELS_DIR, f"{name}.pkl")
        s_path = os.path.join(MODELS_DIR, f"scaler_{name}.pkl")
        if os.path.exists(m_path) and os.path.exists(s_path):
            models[name]  = joblib.load(m_path)
            scalers[name] = joblib.load(s_path)

    if not models:
        return None, None, None

    meta = {}
    if os.path.exists(META_PATH):
        with open(META_PATH) as f:
            meta = json.load(f)

    print(f"[ML Engine] Loaded {len(models)} specialist models: {list(models.keys())}")
    for k, v in meta.get("models", {}).items():
        print(f"  {k:<10} trained on {v['dataset']:<15} "
              f"F1={v['performance']['f1_score']}%  "
              f"specialises: {v['specialises_in']}")

    return models, scalers, meta


_MODELS, _SCALERS, _META = _load()
PRETRAINED = _MODELS is not None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(v) -> float:
    if np.isnan(v) or np.isinf(v):
        return 0.0
    return float(v)


def _severity(score: float) -> str:
    if score > 0.9:   return "Critical"
    elif score > 0.75: return "High"
    elif score > 0.5:  return "Medium"
    return "Low"


def _scale_for(name: str, X: np.ndarray) -> np.ndarray:
    """Apply the scaler that was fitted for this specific model."""
    scaler = _SCALERS[name]
    p99    = _META["models"][name]["p99_bytes_clip"] if _META else 1e9
    X      = X.copy()
    X[:, 1] = np.clip(X[:, 1], 0, p99)
    return scaler.transform(X)


def _score_all(X_raw: np.ndarray) -> Dict[str, np.ndarray]:
    """
    Score X_raw with every loaded specialist model.
    Returns dict: model_name → array of probabilities (0–1).
    """
    scores = {}
    for name, model in _MODELS.items():
        try:
            X_s = _scale_for(name, X_raw)
            scores[name] = model.predict_proba(X_s)[:, 1]
        except Exception as e:
            print(f"[ML Engine] {name} scoring failed: {e}")
    return scores


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_events(events: List[Dict]) -> List[Dict]:
    """
    Score each event using all 3 specialist models.
    Final score = max across all models.
    Falls back to per-request IForest if no saved models exist.
    """
    if not events:
        return []

    df    = pd.DataFrame(events)
    X_raw = df[FEATURES].fillna(0).values.astype(float)

    if PRETRAINED:
        all_scores = _score_all(X_raw)
        # Stack into (n_events, n_models) matrix
        score_matrix = np.column_stack(list(all_scores.values()))
        model_names  = list(all_scores.keys())
        final_scores = score_matrix.max(axis=1)
        best_model_idx = score_matrix.argmax(axis=1)
        threshold = 0.5
    else:
        print("[ML Engine] WARNING: No pre-trained models found. "
              "Run train_model.py first. Falling back to per-request fitting.")
        clf = IForest(contamination=0.15, random_state=42, n_estimators=100)
        clf.fit(X_raw)
        final_scores   = clf.predict_proba(X_raw)[:, 1]
        score_matrix   = final_scores.reshape(-1, 1)
        model_names    = ["iforest"]
        best_model_idx = np.zeros(len(events), dtype=int)
        threshold      = 0.65

    results = []
    for idx, row in df.iterrows():
        score    = _safe(float(final_scores[idx]))
        is_anom  = score > threshold
        rec      = row.to_dict()
        rec["ml_anomaly_score"] = round(score, 4)
        rec["is_anomaly"]       = bool(is_anom)
        rec["ml_severity"]      = _severity(score)
        rec["model_source"]     = "pretrained_specialist" if PRETRAINED else "realtime_fit"

        if PRETRAINED:
            best_name = model_names[best_model_idx[idx]]
            rec["detected_by"] = MODEL_DISPLAY.get(best_name, best_name)
            rec["model_scores"] = {
                MODEL_DISPLAY.get(n, n): round(_safe(float(score_matrix[idx, i])), 4)
                for i, n in enumerate(model_names)
            }

        results.append(rec)

    return results


def compare_models(events: List[Dict]) -> Dict:
    """
    Compare all 3 specialist models on the current event batch.
    Shows per-model metrics against ground-truth event_type labels.
    """
    if not events:
        return {"error": "No events to analyze"}

    df     = pd.DataFrame(events)
    X_raw  = df[FEATURES].fillna(0).values.astype(float)
    y_true = np.array([1 if e.get("event_type") == "attack" else 0 for e in events])

    comparison       = {}
    per_event_scores = {}

    if PRETRAINED:
        all_scores = _score_all(X_raw)
        for name, probs in all_scores.items():
            display = MODEL_DISPLAY.get(name, name)
            predictions = (probs > 0.5).astype(int)
            tp = int(np.sum((predictions == 1) & (y_true == 1)))
            fp = int(np.sum((predictions == 1) & (y_true == 0)))
            fn = int(np.sum((predictions == 0) & (y_true == 1)))
            tn = int(np.sum((predictions == 0) & (y_true == 0)))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            accuracy  = (tp + tn) / len(y_true)
            comparison[display] = {
                "accuracy":           round(accuracy  * 100, 1),
                "precision":          round(precision * 100, 1),
                "recall":             round(recall    * 100, 1),
                "f1_score":           round(f1        * 100, 1),
                "anomalies_detected": int(np.sum(predictions)),
                "avg_anomaly_score":  round(float(np.mean(probs)), 4),
                "confusion_matrix":   {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
                "dataset":            _META["models"][name]["dataset"] if _META else "unknown",
                "specialises_in":     _META["models"][name]["specialises_in"] if _META else "",
                "training_f1":        _META["models"][name]["performance"]["f1_score"] if _META else 0,
            }
            per_event_scores[display] = [_safe(p) for p in probs]
    else:
        # Fallback
        n_neighbors = min(5, len(events) - 1)
        fallback_models = {
            "Isolation Forest": IForest(contamination=0.15, random_state=42, n_estimators=100),
            "KNN":              KNN(contamination=0.15, n_neighbors=n_neighbors),
            "HBOS":             HBOS(contamination=0.15, n_bins=10),
        }
        for name, model in fallback_models.items():
            try:
                model.fit(X_raw)
                probs       = model.predict_proba(X_raw)[:, 1]
                predictions = (probs > 0.65).astype(int)
                tp = int(np.sum((predictions == 1) & (y_true == 1)))
                fp = int(np.sum((predictions == 1) & (y_true == 0)))
                fn = int(np.sum((predictions == 0) & (y_true == 1)))
                tn = int(np.sum((predictions == 0) & (y_true == 0)))
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                accuracy  = (tp + tn) / len(y_true)
                comparison[name] = {
                    "accuracy":           round(accuracy  * 100, 1),
                    "precision":          round(precision * 100, 1),
                    "recall":             round(recall    * 100, 1),
                    "f1_score":           round(f1        * 100, 1),
                    "anomalies_detected": int(np.sum(predictions)),
                    "avg_anomaly_score":  round(float(np.mean(probs)), 4),
                    "confusion_matrix":   {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
                }
                per_event_scores[name] = [_safe(p) for p in probs]
            except Exception as e:
                comparison[name] = {"error": str(e)}

    valid = {k: v for k, v in comparison.items() if "error" not in v}
    best  = max(valid, key=lambda k: valid[k]["f1_score"]) if valid else "Isolation Forest (NSL-KDD)"

    event_comparison = []
    for i in range(min(20, len(events))):
        entry = {
            "index":       i,
            "event_type":  events[i].get("event_type", "unknown"),
            "attack_type": events[i].get("attack_type"),
        }
        for name in per_event_scores:
            entry[name] = round(per_event_scores[name][i], 4)
        event_comparison.append(entry)

    return {
        "total_events":   len(events),
        "total_attacks":  int(np.sum(y_true)),
        "total_normal":   int(np.sum(y_true == 0)),
        "pretrained":     PRETRAINED,
        "training_mode":  _META.get("training_mode", "realtime") if _META else "realtime",
        "scoring_strategy": _META.get("scoring_strategy", "single model") if _META else "single model",
        "models":         comparison,
        "best_model":     best,
        "best_f1":        valid.get(best, {}).get("f1_score", 0),
        "event_comparison": event_comparison,
        "chart_data": [
            {"model": k, **{m: v for m, v in v.items()
                            if m in ["accuracy", "precision", "recall", "f1_score"]}}
            for k, v in comparison.items() if "error" not in v
        ],
    }


def get_model_info() -> Dict:
    """Return metadata about the loaded specialist models."""
    if not PRETRAINED:
        return {
            "pretrained": False,
            "message":    "No pre-trained models found. Run: python train_model.py",
            "models_dir": MODELS_DIR,
        }
    return {
        "pretrained":       True,
        "training_mode":    _META.get("training_mode"),
        "scoring_strategy": _META.get("scoring_strategy"),
        "features":         FEATURES,
        "models": {
            MODEL_DISPLAY.get(k, k): {
                "dataset":        v["dataset"],
                "specialises_in": v["specialises_in"],
                "train_samples":  v["train_samples"],
                "contamination":  v["contamination"],
                "f1_score":       v["performance"]["f1_score"],
                "accuracy":       v["performance"]["accuracy"],
                "recall":         v["performance"]["recall"],
            }
            for k, v in _META.get("models", {}).items()
        },
    }
