from datetime import datetime
import os
import sys

# -------------------------------------------------
# Ensure project root is in PYTHONPATH
# -------------------------------------------------
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
sys.path.append(PROJECT_ROOT)

# -------------------------------------------------
# Fixed mappings (DO NOT CHANGE)
# -------------------------------------------------
CLOUD_PROVIDER_MAP = {
    "AWS": 1,
    "Azure": 2,
    "GCP": 3
}

SERVICE_CATEGORY_MAP = {
    # AWS
    "ec2": 1,
    "iam": 2,
    "s3": 3,
    "cloudtrail": 4,

    # Azure
    "Microsoft.Compute": 5,
    "Microsoft.Authorization": 6,
    "Microsoft.Network": 7,

    # GCP
    "compute.googleapis.com": 8,
    "iam.googleapis.com": 9,
    "appengine.googleapis.com": 10
}

SENSITIVE_OPERATIONS = {
    "CreateUser", "AddUserToGroup", "CreateRole",
    "SetIamPolicy", "TerminateInstances",
    "virtualMachines/delete",
    "compute.instances.delete"
}

# -------------------------------------------------
# Feature extraction (ONE LOG → ONE VECTOR)
# -------------------------------------------------
def extract_features(log):
    # Hour of day
    try:
        hour_of_day = datetime.fromisoformat(
            log.get("timestamp", "").replace("Z", "")
        ).hour
    except Exception:
        hour_of_day = 0

    return {
        "hour_of_day": hour_of_day,

        # Sensitive operation indicator
        "is_sensitive_operation": 1
        if log.get("operation") in SENSITIVE_OPERATIONS
        else 0,

        # Severity REMOVED → neutral placeholder
        "is_error": 0,

        # Service category encoding
        "service_category": SERVICE_CATEGORY_MAP.get(
            log.get("service"), 0
        ),

        # Operation hashing
        "operation_category": hash(
            log.get("operation", "")
        ) % 1000,

        # Cloud provider encoding
        "cloud_provider_id": CLOUD_PROVIDER_MAP.get(
            log.get("cloud_provider"), 0
        )
    }

# -------------------------------------------------
# BUILT-IN TEST
# -------------------------------------------------
if __name__ == "__main__":
    from scripts.load_logs import load_base_logs

    logs = load_base_logs()

    print("\n[TEST] Feature Extraction Output")
    print("--------------------------------")

    features = extract_features(logs[0])

    for k, v in features.items():
        print(f"{k}: {v}")

    print("--------------------------------")
    print("Total features:", len(features))
