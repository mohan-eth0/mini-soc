"""
Centralized MITRE ATT&CK mapping
Framework: MITRE ATT&CK Enterprise
"""

MITRE_MAP = {
    "SSH_BRUTE_FORCE": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force"
    },
    "SSH_VALID_LOGIN": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    "CRON_PERSISTENCE": {
        "tactic": "Persistence",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task / Cron"
    }
}

DEFAULT_MITRE = {
    "tactic": "Unknown",
    "technique_id": "N/A",
    "technique_name": "Unmapped Technique"
}
