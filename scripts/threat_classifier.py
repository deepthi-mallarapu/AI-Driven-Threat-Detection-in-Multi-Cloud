import os
import sys
import joblib
import pandas as pd

# -------------------------------------------------
# Ensure project root is in PYTHONPATH
# -------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)

from scripts.feature_extraction import extract_features

# -------------------------------------------------
# Load trained anomaly detection model
# -------------------------------------------------
MODEL_PATH = "models/anomaly_model.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("Anomaly model not found. Train the model first.")

anomaly_model = joblib.load(MODEL_PATH)

# -------------------------------------------------
# ML anomaly check
# -------------------------------------------------
def is_anomalous(log):
    features = extract_features(log)
    df = pd.DataFrame([features])
    return anomaly_model.predict(df)[0] == -1

# -------------------------------------------------
# Operation categories
# -------------------------------------------------
IAM_POLICY_OPS = {
    "SetIamPolicy",
    "roleAssignments/write",
    "CreateRole"
}

IAM_USER_OPS = {
    "CreateUser",
    "AddUserToGroup"
}

DESTRUCTIVE_OPS = {
    "TerminateInstances",
    "virtualMachines/delete",
    "compute.instances.delete"
}

CONFIG_OPS = {
    "AuthorizeSecurityGroupIngress",
    "RevokeSecurityGroupIngress",
    "networkSecurityGroups/write",
    "firewalls.patch"
}

# -------------------------------------------------
# Hybrid Threat Classifier (NO SEVERITY)
# -------------------------------------------------
def classify_threat(log):

    operation = log.get("operation", "")
    message = log.get("message", "").lower()
    hour = extract_features(log)["hour_of_day"]

    anomalous = is_anomalous(log)

    # ---------------------------------------------
    # 1️⃣ Destructive Activity (ALWAYS)
    # ---------------------------------------------
    if operation in DESTRUCTIVE_OPS:
        return {
            "detected_threat": "Destructive Activity",
            "risk_level": "Critical",
            "confidence": 0.95,
            "recommended_action": "Immediate investigation and resource protection"
        }

    # ---------------------------------------------
    # 2️⃣ Privilege Escalation (Policy-level)
    # ---------------------------------------------
    if operation in IAM_POLICY_OPS:
        return {
            "detected_threat": "Privilege Escalation",
            "risk_level": "High",
            "confidence": 0.85 if anomalous else 0.70,
            "recommended_action": "Review IAM policy changes and rotate credentials"
        }

    # ---------------------------------------------
    # 3️⃣ Unauthorized Access Attempt (DIRECT RULE)
    # ---------------------------------------------
    if (
        "accessdenied" in message or
        "unauthorized" in message or
        "permission denied" in message
    ):
        return {
            "detected_threat": "Unauthorized Access Attempt",
            "risk_level": "Medium",
            "confidence": 0.80,
            "recommended_action": "Monitor source IP and enforce access controls"
        }

    # ---------------------------------------------
    # 4️⃣ Configuration Tampering (DIRECT RULE)
    # ---------------------------------------------
    if operation in CONFIG_OPS:
        return {
            "detected_threat": "Configuration Tampering",
            "risk_level": "High",
            "confidence": 0.85,
            "recommended_action": "Review configuration changes and restore baseline"
        }

    # ---------------------------------------------
    # 5️⃣ Account Compromise (ML-GATED)
    # ---------------------------------------------
   # 5️⃣ Account Compromise (RULE-FIRST)
    if operation in IAM_USER_OPS and hour < 6:
        return {
            "detected_threat": "Account Compromise",
            "risk_level": "High",
            "confidence": 0.85 if anomalous else 0.65,
            "recommended_action": "Disable account temporarily and rotate credentials"
        }


    # ---------------------------------------------
    # 6️⃣ Suspicious Activity (ML-GATED)
    # ---------------------------------------------
    # 6️⃣ Suspicious Activity (RULE-FIRST)
    if (
        "failed" in message or
        "suspicious" in message or
        "multiple" in message
    ):
        return {
            "detected_threat": "Suspicious Activity",
            "risk_level": "Medium",
            "confidence": 0.75 if anomalous else 0.60,
            "recommended_action": "Monitor and investigate abnormal behavior"
        }


    # ---------------------------------------------
    # 7️⃣ Normal Activity
    # ---------------------------------------------
    return {
        "detected_threat": "Normal Activity",
        "risk_level": "Low",
        "confidence": 0.05,
        "recommended_action": "Allow"
    }
