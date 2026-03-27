import json
import random
import copy
import os
from datetime import datetime, timedelta

# -------------------------------------------------
# Paths
# -------------------------------------------------
BASE_DIR = "data/cloud_logs"

BASE_FILES = {
    "AWS": "aws_base.json",
    "Azure": "azure_base.json",
    "GCP": "gcp_base.json"
}

OUTPUT_FILES = {
    "AWS": "aws_logs.json",
    "Azure": "azure_logs.json",
    "GCP": "gcp_logs.json"
}

# -------------------------------------------------
# Controlled values
# -------------------------------------------------
USERS = ["admin", "devops", "service-account", "automation", "attacker"]
REGIONS = ["us-east-1", "us-west-2", "centralus", "europe-west1", "asia-south1"]
IPS = ["10.0.0.5", "10.0.1.12", "192.168.1.10"]

# -------------------------------------------------
# Attack patterns per cloud
# -------------------------------------------------
ATTACK_PATTERNS = {
    "AWS": [
        ("iam", "CreateUser", "HIGH"),
        ("iam", "AddUserToGroup", "HIGH"),
        ("ec2", "TerminateInstances", "CRITICAL")
    ],
    "Azure": [
        ("Microsoft.Authorization", "roleAssignments/write", "HIGH"),
        ("Microsoft.Compute", "virtualMachines/delete", "CRITICAL")
    ],
    "GCP": [
        ("iam.googleapis.com", "SetIamPolicy", "HIGH"),
        ("compute.googleapis.com", "compute.instances.delete", "CRITICAL")
    ]
}

# -------------------------------------------------
# Helpers
# -------------------------------------------------
def load_logs(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def shift_time(timestamp, minutes):
    base = datetime.fromisoformat(timestamp.replace("Z", ""))
    return (base + timedelta(minutes=minutes)).isoformat() + "Z"

# -------------------------------------------------
# Normal augmentation
# -------------------------------------------------
def generate_normal_variants(log, count=4):
    variants = []
    for _ in range(count):
        l = copy.deepcopy(log)
        l["timestamp"] = shift_time(log["timestamp"], random.randint(-180, 180))
        l["user"] = random.choice(USERS[:-1])  # exclude attacker
        l["region"] = random.choice(REGIONS)
        l["source_ip"] = random.choice(IPS)
        l["severity"] = "INFO"
        variants.append(l)
    return variants

# -------------------------------------------------
# Attack generation
# -------------------------------------------------
def generate_attack_log(base_log, service, operation, severity):
    l = copy.deepcopy(base_log)
    l["service"] = service
    l["operation"] = operation
    l["severity"] = severity
    l["user"] = "attacker"
    l["message"] = f"Suspicious operation detected: {operation}"
    l["timestamp"] = shift_time(base_log["timestamp"], random.randint(1, 15))
    return l

# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    for cloud, base_file in BASE_FILES.items():
        base_path = os.path.join(BASE_DIR, base_file)
        output_path = os.path.join(BASE_DIR, OUTPUT_FILES[cloud])

        base_logs = load_logs(base_path)
        synthetic_logs = []

        for log in base_logs:
            # Normal behavior expansion
            synthetic_logs.extend(generate_normal_variants(log))

            # Explicit attack injection
            for svc, op, sev in ATTACK_PATTERNS[cloud]:
                synthetic_logs.append(
                    generate_attack_log(log, svc, op, sev)
                )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(synthetic_logs, f, indent=2)

        print(f"[SUCCESS] {cloud}: Generated {len(synthetic_logs)} synthetic logs")

if __name__ == "__main__":
    main()
