#🛡️ Mini-SOC v1.0.0 — Host-Based Detection & Alert Correlation
Version 1.0.0 focuses on local, host-based detection and SOC-style alerting.  
Cloud deployment and email alerting are planned for v2.0.0.


Mini-SOC is a lightweight **Security Operations Center (SOC) simulation tool** written in Python.  
It detects suspicious SSH activity on a Linux host, correlates raw detections to reduce alert noise, and generates **SOC-style alerts and structured security reports**.

This project focuses on **detection engineering fundamentals** rather than full SIEM deployment.

---

## 🎯 Key Objectives

- Detect SSH-based attacks using log analysis
- Reduce alert fatigue through correlation and aggregation
- Present alerts in an analyst-friendly format
- Generate machine-readable security reports (JSON)
- Demonstrate real SOC workflows in a simple, inspectable system

---

## 🔍 Features

- SSH log collection (`auth.log`, `journalctl`)
- Rule-based detection engine
- Alert aggregation (deduplication + count)
- SOC-style terminal alerts
- Executive-ready JSON reports
- Optional automated response hook
- Pytest-based rule validation

---

## 🧠 How It Works (Detection Flow)


---

## 📂 Project Structure

```text
mini-soc/
├── collectors/          # Log collection modules
├── engine/              # Detection, alerting, reporting logic
├── reports/             # Generated SOC reports (JSON)
├── response/            # Optional active response scripts
├── rules/               # Detection rules
├── incidents.db         # SQLite evidence store
├── main.py              # Main execution pipeline
├── README.md            # Project documentation
└── requirements.txt



Terminal output:-

======================================================================
[ALERT] SSH_BRUTE_FORCE
 First Seen : 2025-12-27 13:18:11
 Severity   : HIGH
 Source IP  : 10.1.1.54
 Count      : 4
======================================================================

Example report(JSON):-


{
  "generated_at": "2025-12-27T13:18:11",
  "total_alerts": 6,
  "severity_breakdown": {
    "HIGH": 3,
    "MEDIUM": 3
  },
  "alerts": [
    {
      "rule": "SSH_BRUTE_FORCE",
      "severity": "HIGH",
      "ip": "10.1.1.54",
      "first_seen": "2025-12-27 13:18:11",
      "count": 4
    }
  ]
}


## 🎯 MITRE ATT&CK Coverage (v1.0.0)

| Detection | Technique ID | Technique Name |
|---------|-------------|----------------|
| SSH Brute Force | T1110 | Brute Force |
| SSH Success After Fail | T1110.001 | Password Guessing |
| Repeated Authentication Attempts | T1078 | Valid Accounts |
| SSH Remote Access | T1021.004 | Remote Services: SSH |

MITRE ATT&CK mapping is applied at detection time and preserved in incident records.
happy



🚀 Future Enhancements:-

Alert suppression / cooldown windows

Email or Slack alerting

Daily SOC summary reports

SIEM-compatible export formats
