import json
import os
from datetime import datetime

REPORT_DIR = "reports"

def write_alerts(alerts):
    os.makedirs(REPORT_DIR, exist_ok=True)

    summary = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "severity_breakdown": {},
        "alerts": alerts
    }

    for alert in alerts:
        sev = alert["severity"]
        summary["severity_breakdown"][sev] = (
            summary["severity_breakdown"].get(sev, 0) + 1
        )

    filename = "latest_alerts.json"  # overwrite each run
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w") as f:
        json.dump(summary, f, indent=2)

    return path
