import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

# -------------------------------------------------
# Ensure project root is in PYTHONPATH (Windows safe)
# -------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)

from scripts.load_logs import load_base_logs
from scripts.feature_extraction import extract_features

# -------------------------------------------------
# Train anomaly detection model (NORMAL DATA ONLY)
# -------------------------------------------------
def train_anomaly_model():
    print("[INFO] Loading base (normal) logs...")
    logs = load_base_logs()

    if not logs:
        raise RuntimeError("No base logs found. Training cannot proceed.")

    print("[INFO] Extracting features...")
    feature_rows = []
    for log in logs:
        feature_rows.append(extract_features(log))

    df = pd.DataFrame(feature_rows)

    print(f"[INFO] Feature matrix shape: {df.shape}")

    # -------------------------------------------------
    # Isolation Forest (Conservative Configuration)
    # -------------------------------------------------
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,   # low → avoid false positives
        random_state=42
    )

    print("[INFO] Training Isolation Forest model...")
    model.fit(df)

    # -------------------------------------------------
    # Save trained model
    # -------------------------------------------------
    os.makedirs("models", exist_ok=True)
    model_path = "models/anomaly_model.pkl"
    joblib.dump(model, model_path)

    print(f"[SUCCESS] Model trained and saved at: {model_path}")

# -------------------------------------------------
# Run training
# -------------------------------------------------
if __name__ == "__main__":
    train_anomaly_model()
