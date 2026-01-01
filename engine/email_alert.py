import smtplib
from email.message import EmailMessage
import json

def send_email(incident, config):
    msg = EmailMessage()
    msg["Subject"] = f"[Mini-SOC] {incident['severity']} Incident from {incident['source_ip']}"
    msg["From"] = config["from"]
    msg["To"] = config["to"]

    body = json.dumps(incident, indent=2)
    msg.set_content(body)

    with smtplib.SMTP(config["host"], config["port"]) as server:
        server.starttls()
        server.login(config["user"], config["password"])
        server.send_message(msg)
