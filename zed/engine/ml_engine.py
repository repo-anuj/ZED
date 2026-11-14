"""
ZED Machine Learning Anomaly Detection Engine
Uses scikit-learn Isolation Forest to detect zero-day behaviors that evade signature rules.
Trains on a normal system baseline and scores live behavior vectors in real time.
"""

from pathlib import Path
import numpy as np
import joblib
from typing import Optional, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest

from zed.config import MODEL_PATH, ML_CONTAMINATION, ML_N_ESTIMATORS
from zed.models import BehaviorFeatures, Alert, Severity
from zed.db import db


class MLEngine:
    def __init__(self, model_path: Path = MODEL_PATH):
        self.model_path = model_path
        self.model: Optional[IsolationForest] = None
        self.is_trained = False
        self.baseline_stats: Dict[str, Any] = {}
        self._load_or_train()

    def _load_or_train(self):
        """Attempts to load existing trained model, or trains default baseline if missing."""
        if self.model_path.exists():
            try:
                saved_data = joblib.load(self.model_path)
                if isinstance(saved_data, dict):
                    self.model = saved_data.get("model")
                    self.baseline_stats = saved_data.get("stats", {})
                else:
                    self.model = saved_data
                self.is_trained = True
                return
            except Exception:
                pass

        # If not present, train an initial baseline profile
        self.train_baseline()

    def train_baseline(self, samples_count: int = 400) -> Dict[str, Any]:
        """
        Synthesizes/samples a realistic normal baseline profile of Linux Mint endpoint activity:
        - Routine background daemons, terminal commands, web browsing, idle states.
        - Low process spawn rate, normal file changes, quiet auth, moderate CPU variations.
        """
        np.random.seed(42)

        # Baseline distributions for normal Linux Mint usage:
        # [new_proc_rate, unique_binaries, file_mod_rate, net_conn_rate, distinct_dest_ips, auth_fail_rate, cpu_entropy]
        new_proc_rate = np.random.gamma(shape=1.2, scale=0.4, size=samples_count)       # Mean ~0.5 proc/s
        unique_binaries = np.random.poisson(lam=1.5, size=samples_count)                 # 1-3 distinct bins
        file_mod_rate = np.random.exponential(scale=0.8, size=samples_count)             # Normal file saves
        net_conn_rate = np.random.exponential(scale=0.5, size=samples_count)             # Routine connections
        distinct_dest_ips = np.random.poisson(lam=1.0, size=samples_count)               # 0-2 external IPs
        auth_fail_rate = np.zeros(samples_count)                                         # 0 failed logins
        cpu_entropy = np.random.normal(loc=5.0, scale=3.0, size=samples_count)           # Normal CPU flutter
        cpu_entropy = np.clip(cpu_entropy, 0.0, 25.0)

        # Stack into 2D feature matrix
        X_train = np.column_stack([
            new_proc_rate,
            unique_binaries,
            file_mod_rate,
            net_conn_rate,
            distinct_dest_ips,
            auth_fail_rate,
            cpu_entropy
        ])

        # Initialize & fit Isolation Forest
        model = IsolationForest(
            n_estimators=ML_N_ESTIMATORS,
            contamination=ML_CONTAMINATION,
            random_state=42,
            n_jobs=1
        )
        model.fit(X_train)

        # Compute baseline feature averages for deviation explanation
        means = np.mean(X_train, axis=0)
        stds = np.std(X_train, axis=0) + 1e-5

        self.model = model
        self.is_trained = True
        self.baseline_stats = {
            "samples": samples_count,
            "means": means.tolist(),
            "stds": stds.tolist(),
            "feature_names": BehaviorFeatures.feature_names(),
            "contamination": ML_CONTAMINATION
        }

        # Persist model
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "stats": self.baseline_stats}, self.model_path)

        # Record in DB
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO ml_baseline (trained_at, sample_count, contamination, status) VALUES (?, ?, ?, ?)",
                (db.datetime_now() if hasattr(db, "datetime_now") else "now", samples_count, ML_CONTAMINATION, "ACTIVE")
            )
            conn.commit()

        return {
            "status": "TRAINED",
            "samples": samples_count,
            "contamination": ML_CONTAMINATION,
            "estimators": ML_N_ESTIMATORS
        }

    def score_features(self, features: BehaviorFeatures) -> Tuple[Optional[Alert], float, Dict[str, Any]]:
        """
        Evaluates a live feature window with the Isolation Forest model.
        Returns: (Alert or None, raw_anomaly_score, deviation_breakdown)
        """
        if not self.is_trained or self.model is None:
            return None, 0.0, {}

        feature_vector = np.array([features.to_array()])
        # Decision function: negative values indicate anomalies, positive indicates normal
        raw_score = float(self.model.decision_function(feature_vector)[0])
        prediction = int(self.model.predict(feature_vector)[0])  # 1 for normal, -1 for anomaly

        # Determine which features diverged most from baseline
        deviations = {}
        means = self.baseline_stats.get("means", [0]*7)
        stds = self.baseline_stats.get("stds", [1]*7)
        names = BehaviorFeatures.feature_names()

        for i, val in enumerate(features.to_array()):
            z_score = (val - means[i]) / stds[i]
            deviations[names[i]] = {
                "observed": round(val, 2),
                "baseline_mean": round(means[i], 2),
                "z_score": round(float(z_score), 2)
            }

        # If flagged as anomaly (-1) or score is deeply negative (< -0.05)
        if prediction == -1 or raw_score < -0.05:
            # Identify highest deviating features
            top_deviations = sorted(
                deviations.items(),
                key=lambda item: abs(item[1]["z_score"]),
                reverse=True
            )[:3]

            reason_str = ", ".join(
                f"{name}={info['observed']} (baseline ~{info['baseline_mean']})"
                for name, info in top_deviations
            )

            severity = Severity.HIGH if raw_score > -0.15 else Severity.CRITICAL

            alert = Alert(
                source="ML_ANOMALY",
                severity=severity,
                technique_id="ZERO-DAY-ML",
                rule_name="Zero-Day Behavioral Anomaly (Isolation Forest)",
                process_name="anomalous_burst",
                pid=None,
                details=f"Unsupervised ML flagged multi-vector deviation (Score: {raw_score:.3f}). Anomalous metrics: {reason_str}",
                anomaly_score=round(raw_score, 4),
                response_action="LOGGED"
            )
            return alert, raw_score, deviations

        return None, raw_score, deviations


# Global ML Engine instance
ml_engine = MLEngine()
