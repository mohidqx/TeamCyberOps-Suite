"""
TeamCyberOps Suite v3 — Notify Module
Sends alerts via Slack, Discord, and Email
"""
import json
import smtplib
import urllib.request
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

CFG_PATH = Path(__file__).parent.parent / "config.json"


def _cfg() -> dict:
    with open(CFG_PATH) as f:
        return json.load(f)


def notify_all(message: str, title: str = "TeamCyberOps Alert") -> dict:
    """Send notification to all configured channels."""
    cfg = _cfg()["notify"]
    results = {}
    if cfg.get("slack_webhook"):
        results["slack"] = send_slack(message, cfg["slack_webhook"])
    if cfg.get("discord_webhook"):
        results["discord"] = send_discord(message, title, cfg["discord_webhook"])
    email_cfg = cfg.get("email", {})
    if email_cfg.get("username") and email_cfg.get("recipient"):
        results["email"] = send_email(title, message, email_cfg)
    return results


def send_slack(message: str, webhook_url: str = None) -> bool:
    try:
        if not webhook_url:
            webhook_url = _cfg()["notify"]["slack_webhook"]
        payload = json.dumps({"text": f"*TeamCyberOps* 🔴\n{message}"}).encode()
        req = urllib.request.Request(webhook_url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"[Slack] Error: {e}")
        return False


def send_discord(message: str, title: str = "Alert", webhook_url: str = None) -> bool:
    try:
        if not webhook_url:
            webhook_url = _cfg()["notify"]["discord_webhook"]
        payload = json.dumps({
            "embeds": [{
                "title": f"🔴 {title}",
                "description": message,
                "color": 16711680,
                "footer": {"text": "TeamCyberOps Suite v3"}
            }]
        }).encode()
        req = urllib.request.Request(webhook_url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"[Discord] Error: {e}")
        return False


def send_email(subject: str, body: str, email_cfg: dict = None) -> bool:
    try:
        if not email_cfg:
            email_cfg = _cfg()["notify"]["email"]
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[TeamCyberOps] {subject}"
        msg["From"] = email_cfg["username"]
        msg["To"] = email_cfg["recipient"]
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            server.starttls()
            server.login(email_cfg["username"], email_cfg["password"])
            server.sendmail(email_cfg["username"], email_cfg["recipient"], msg.as_string())
        return True
    except Exception as e:
        print(f"[Email] Error: {e}")
        return False


def test_notification(channel: str) -> str:
    """Test a specific notification channel."""
    msg = "✅ TeamCyberOps Suite v3 — Test notification successful!"
    if channel == "slack":
        ok = send_slack(msg)
    elif channel == "discord":
        ok = send_discord(msg, "Test Alert")
    elif channel == "email":
        ok = send_email("Test Alert", msg)
    else:
        return "Unknown channel"
    return "✅ Sent successfully!" if ok else "❌ Failed — check config"
