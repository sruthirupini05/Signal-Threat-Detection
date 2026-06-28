# =============================================================
# anomaly_detection.py — Threat / Anomaly Detection Module
# Uses Isolation Forest to detect suspicious network behavior
# =============================================================

import numpy as np
import json
import os
import pickle
import time
from datetime import datetime
from collections import deque

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────

# Rolling window of recent traffic snapshots (per pair)
_traffic_history = {}   # key: "ip_a↔ip_b" → deque of feature vectors
WINDOW_SIZE      = 50   # number of snapshots to keep per pair


def extract_features(status_dict):
    """
    Convert a communication_monitor.get_status() dict into a feature vector.

    Features:
        [0] packet_count
        [1] bytes_total
        [2] bytes_per_packet  (avg packet size)
        [3] is_active         (0 or 1)
        [4] protocol_diversity (number of unique protocols used)
        [5] tcp_ratio         (TCP packets / total)
        [6] udp_ratio         (UDP packets / total)
        [7] icmp_ratio        (ICMP packets / total)
        [8] duration_secs
        [9] pkt_rate          (packets per second, approx)
    """
    pc   = status_dict.get("packet_count", 0)
    bt   = status_dict.get("bytes_total",  0)
    dur  = status_dict.get("duration_secs", 0) + 1e-6

    protos  = status_dict.get("protocols", {})
    total_p = sum(protos.values()) + 1e-6

    tcp_count  = sum(v for k, v in protos.items() if k.startswith("TCP"))
    udp_count  = sum(v for k, v in protos.items() if k.startswith("UDP"))
    icmp_count = protos.get("ICMP", 0)

    features = [
        pc,                                   # 0
        bt,                                   # 1
        bt / (pc + 1e-6),                     # 2 avg bytes/packet
        1 if status_dict.get("status") == "ACTIVE" else 0,  # 3
        len(protos),                          # 4 protocol diversity
        tcp_count  / total_p,                 # 5
        udp_count  / total_p,                 # 6
        icmp_count / total_p,                 # 7
        dur,                                  # 8
        pc / dur,                             # 9 packet rate
    ]
    return np.array(features, dtype=np.float32)


def push_observation(pair_key, status_dict):
    """Add a new traffic observation to the rolling window."""
    if pair_key not in _traffic_history:
        _traffic_history[pair_key] = deque(maxlen=WINDOW_SIZE)
    vec = extract_features(status_dict)
    _traffic_history[pair_key].append(vec)


# ─────────────────────────────────────────
# MODEL TRAINING (baseline = normal traffic)
# ─────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps sklearn IsolationForest.
    Train on 'normal' traffic, then predict anomalies.
    """

    def __init__(self, contamination=0.05, n_estimators=200, random_state=42):
        self.contamination = contamination
        self.model  = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler  = StandardScaler()
        self.trained = False
        self.threshold = None   # custom score threshold (optional)

    # ── Training ─────────────────────────

    def fit(self, X):
        """
        Train on a numpy array of feature vectors (normal traffic).
        X shape: (n_samples, 10)
        """
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.trained = True

        # Compute score distribution on training data
        scores = self.model.score_samples(X_scaled)
        self.threshold = np.percentile(scores, self.contamination * 100)
        print(f"[✓] AnomalyDetector trained on {len(X)} samples")
        print(f"    Score threshold (p{int(self.contamination*100)}): {self.threshold:.4f}")
        return self

    def fit_from_history(self, pair_key=None):
        """
        Train using collected _traffic_history.
        If pair_key is None, use all pairs combined.
        """
        if pair_key:
            data = list(_traffic_history.get(pair_key, []))
        else:
            data = []
            for hist in _traffic_history.values():
                data.extend(hist)

        if len(data) < 10:
            print("[!] Not enough history to train (need ≥10 samples). Collecting ...")
            return self

        X = np.stack(data)
        return self.fit(X)

    # ── Prediction ───────────────────────

    def predict(self, feature_vec):
        """
        Predict if a single feature vector is anomalous.
        Returns dict with:
          is_anomaly : bool
          score      : float (lower = more anomalous; threshold ~ -0.1)
          severity   : "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
          reason     : human-readable explanation
        """
        if not self.trained:
            return {
                "is_anomaly": False,
                "score":      0.0,
                "severity":   "NONE",
                "reason":     "Detector not trained yet",
            }

        vec = np.array(feature_vec, dtype=np.float32).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)

        label = self.model.predict(vec_scaled)[0]     # 1 = normal, -1 = anomaly
        score = self.model.score_samples(vec_scaled)[0]

        is_anomaly = label == -1

        # Severity based on score gap below threshold
        if not is_anomaly:
            severity = "NONE"
        else:
            gap = self.threshold - score  # how far below threshold
            if gap < 0.05:
                severity = "LOW"
            elif gap < 0.15:
                severity = "MEDIUM"
            elif gap < 0.30:
                severity = "HIGH"
            else:
                severity = "CRITICAL"

        reason = _explain(feature_vec, is_anomaly)

        return {
            "is_anomaly": is_anomaly,
            "score":      float(score),
            "severity":   severity,
            "reason":     reason,
            "timestamp":  datetime.now().strftime("%H:%M:%S"),
        }

    def predict_from_status(self, status_dict):
        """Convenience: predict directly from a get_status() dict."""
        vec = extract_features(status_dict)
        return self.predict(vec)

    # ── Save / Load ──────────────────────

    def save(self, path="model/anomaly_detector.pkl"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler,
                         "threshold": self.threshold, "trained": self.trained}, f)
        print(f"[✓] AnomalyDetector saved → {path}")

    def load(self, path="model/anomaly_detector.pkl"):
        with open(path, "rb") as f:
            state = pickle.load(f)
        self.model     = state["model"]
        self.scaler    = state["scaler"]
        self.threshold = state["threshold"]
        self.trained   = state["trained"]
        print(f"[✓] AnomalyDetector loaded ← {path}")
        return self


# ─────────────────────────────────────────
# EXPLAINABILITY
# ─────────────────────────────────────────

def _explain(feature_vec, is_anomaly):
    """Generate a human-readable reason for the anomaly decision."""
    pc, bt, bpp, active, proto_div, tcp_r, udp_r, icmp_r, dur, pkt_rate = feature_vec

    reasons = []
    if pkt_rate > 1000:
        reasons.append(f"Very high packet rate ({pkt_rate:.0f} pkt/s)")
    if bpp > 10_000:
        reasons.append(f"Unusually large packets ({bpp:.0f} B avg)")
    if proto_div > 8:
        reasons.append(f"High protocol diversity ({int(proto_div)} protocols)")
    if icmp_r > 0.5:
        reasons.append(f"High ICMP ratio ({icmp_r*100:.0f}%) — possible ping flood")
    if udp_r > 0.9:
        reasons.append(f"Almost all UDP — possible UDP flood or scan")
    if bt > 100_000_000:
        reasons.append(f"Very high data volume ({bt/1e6:.1f} MB)")

    if not reasons:
        return "Anomalous traffic pattern detected by Isolation Forest" if is_anomaly \
               else "Traffic within normal parameters"

    return " | ".join(reasons)


# ─────────────────────────────────────────
# ALERT SYSTEM
# ─────────────────────────────────────────

class AlertManager:
    """Manages threat alerts with cooldown to prevent spam."""

    def __init__(self, cooldown_secs=30):
        self.cooldown_secs = cooldown_secs
        self._last_alert   = {}  # pair_key → timestamp
        self.alert_log     = []

    def maybe_alert(self, pair_key, prediction):
        """Issue alert if anomaly and not in cooldown."""
        if not prediction["is_anomaly"]:
            return None

        now = time.time()
        last = self._last_alert.get(pair_key, 0)
        if now - last < self.cooldown_secs:
            return None  # still in cooldown

        self._last_alert[pair_key] = now

        alert = {
            "timestamp":  prediction["timestamp"],
            "pair":       pair_key,
            "severity":   prediction["severity"],
            "score":      prediction["score"],
            "reason":     prediction["reason"],
        }
        self.alert_log.append(alert)
        self._print_alert(alert)
        return alert

    def _print_alert(self, alert):
        sev = alert["severity"]
        icons = {"LOW": "⚠️", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}
        icon = icons.get(sev, "⚠️")
        print(f"\n{icon}  THREAT DETECTED [{sev}] @ {alert['timestamp']}")
        print(f"   Pair     : {alert['pair']}")
        print(f"   Score    : {alert['score']:.4f}")
        print(f"   Reason   : {alert['reason']}\n")

    def save_log(self, path="data/alert_log.json"):
        os.makedirs("data", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.alert_log, f, indent=2)

    def recent_alerts(self, n=10):
        return self.alert_log[-n:]


# ─────────────────────────────────────────
# SYNTHETIC NORMAL TRAFFIC GENERATOR
# (for initial training when no history exists)
# ─────────────────────────────────────────

def generate_normal_traffic(n=500, seed=42):
    """
    Generate synthetic 'normal' traffic feature vectors.
    Used to bootstrap the detector before real data is collected.
    """
    rng = np.random.RandomState(seed)

    # Normal traffic profile:
    # - moderate packet rates (10-200 pkt/s)
    # - typical packet sizes (100-1500 B)
    # - mostly TCP/UDP
    # - short-to-medium duration

    pc       = rng.randint(5, 5000, n).astype(float)
    bt       = pc * rng.uniform(100, 1400, n)
    bpp      = bt / (pc + 1)
    active   = rng.choice([0, 1], n, p=[0.3, 0.7]).astype(float)
    proto_d  = rng.randint(1, 5, n).astype(float)
    tcp_r    = rng.beta(5, 2, n)
    udp_r    = 1 - tcp_r - rng.uniform(0, 0.05, n)
    udp_r    = np.clip(udp_r, 0, 1)
    icmp_r   = 1 - tcp_r - udp_r
    icmp_r   = np.clip(icmp_r, 0, 0.1)
    dur      = rng.uniform(1, 300, n)
    pkt_rate = pc / (dur + 1)

    X = np.column_stack([pc, bt, bpp, active, proto_d,
                         tcp_r, udp_r, icmp_r, dur, pkt_rate])
    return X


# ─────────────────────────────────────────
# CONVENIENCE: LOAD OR CREATE DETECTOR
# ─────────────────────────────────────────

def load_or_create_detector():
    """
    Load a saved detector or create and train a new one
    on synthetic normal traffic.
    """
    path = "model/anomaly_detector.pkl"
    det  = AnomalyDetector()

    if os.path.exists(path):
        det.load(path)
    else:
        print("[!] No saved detector found. Training on synthetic baseline ...")
        X_normal = generate_normal_traffic(n=1000)
        det.fit(X_normal)
        det.save(path)

    return det


# ─────────────────────────────────────────
# ENTRY POINT / DEMO
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Anomaly Detection Demo")
    print("=" * 60)

    det   = load_or_create_detector()
    mgr   = AlertManager(cooldown_secs=10)

    # Simulate traffic events
    scenarios = [
        # Normal browsing
        {"packet_count": 120, "bytes_total": 85000,  "status": "ACTIVE",
         "protocols": {"TCP/443": 90, "UDP/53": 30},  "duration_secs": 60},
        # Normal file transfer
        {"packet_count": 800, "bytes_total": 6000000, "status": "ACTIVE",
         "protocols": {"TCP/445": 800},               "duration_secs": 120},
        # ANOMALY: ping flood
        {"packet_count": 5000, "bytes_total": 300000,  "status": "ACTIVE",
         "protocols": {"ICMP": 5000},                  "duration_secs": 10},
        # ANOMALY: port scan (many protocols)
        {"packet_count": 2000, "bytes_total": 50000,  "status": "ACTIVE",
         "protocols": {f"TCP/{p}": 1 for p in range(2000)}, "duration_secs": 5},
        # ANOMALY: data exfiltration
        {"packet_count": 100,  "bytes_total": 500_000_000, "status": "ACTIVE",
         "protocols": {"TCP/443": 100},               "duration_secs": 30},
    ]

    labels = ["Normal browsing", "File transfer", "Ping flood (ANOMALY)",
              "Port scan (ANOMALY)", "Data exfiltration (ANOMALY)"]

    print(f"\n{'Scenario':<30} {'Status':<10} {'Score':>8} Severity")
    print("-" * 65)

    for scenario, label in zip(scenarios, labels):
        pred = det.predict_from_status(scenario)
        mgr.maybe_alert("demo_pair", pred)
        flag = "⚠️" if pred["is_anomaly"] else "✓"
        print(f"  {label:<28} {pred['severity']:<10} {pred['score']:>8.4f}  {flag}")

    print(f"\n[✓] Alert log has {len(mgr.alert_log)} entries")
    mgr.save_log()
