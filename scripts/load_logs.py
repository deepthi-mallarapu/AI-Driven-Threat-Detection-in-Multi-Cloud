import json
import os

# -------------------------------------------------
# Base directory for cloud logs
# -------------------------------------------------
LOG_DIR = "data/cloud_logs"

BASE_FILES = [
    "aws_base.json",
    "azure_base.json",
    "gcp_base.json"
]

SYNTHETIC_FILES = [
    "aws_logs.json",
    "azure_logs.json",
    "gcp_logs.json"
]

# -------------------------------------------------
# Load a JSON file safely
# -------------------------------------------------
def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

        # Ensure list format
        if isinstance(data, dict):
            return [data]
        return data

# -------------------------------------------------
# Normalize a single log into common schema
# -------------------------------------------------
def normalize_log(log):
    return {
        "cloud_provider": log.get("cloud_provider", "Unknown"),
        "timestamp": log.get("timestamp"),
        "service": log.get("service", "Unknown"),
        "operation": log.get("operation", "Unknown"),
        "user": log.get("user", "Unknown"),
        "source_ip": log.get("source_ip", "0.0.0.0"),
        "region": log.get("region", "Unknown"),
        "severity": log.get("severity", "INFO"),
        "message": log.get("message", ""),
        "raw_event_type": log.get("raw_event_type", "Unknown")
    }

# -------------------------------------------------
# Load ONLY base (normal) logs
# (USED FOR ML TRAINING)
# -------------------------------------------------
def load_base_logs():
    logs = []

    for file_name in BASE_FILES:
        path = os.path.join(LOG_DIR, file_name)

        if not os.path.exists(path):
            print(f"[WARN] Missing file: {path}")
            continue

        raw_logs = load_json_file(path)
        for log in raw_logs:
            logs.append(normalize_log(log))

    print(f"[INFO] Loaded {len(logs)} BASE (normal) logs")
    return logs

# -------------------------------------------------
# Load ONLY synthetic logs
# (USED FOR TESTING / UI / RULE VALIDATION)
# -------------------------------------------------
def load_synthetic_logs():
    logs = []

    for file_name in SYNTHETIC_FILES:
        path = os.path.join(LOG_DIR, file_name)

        if not os.path.exists(path):
            print(f"[WARN] Missing file: {path}")
            continue

        raw_logs = load_json_file(path)
        for log in raw_logs:
            logs.append(normalize_log(log))

    print(f"[INFO] Loaded {len(logs)} SYNTHETIC logs")
    return logs

# -------------------------------------------------
# BUILT-IN TEST
# -------------------------------------------------
if __name__ == "__main__":
    print("\n[TEST] Loading BASE logs")
    base_logs = load_base_logs()
    print("Sample BASE log:")
    print(base_logs[0])

    print("\n[TEST] Loading SYNTHETIC logs")
    synthetic_logs = load_synthetic_logs()
    print("Sample SYNTHETIC log:")
    print(synthetic_logs[0])
