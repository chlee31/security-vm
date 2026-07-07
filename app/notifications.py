import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

from app.database import insert_notification_event, latest_sent_notification


def email_settings(config):
    settings = config.get("notifications", {}).get("email", {})
    return {
        "enabled": bool(settings.get("enabled", False)),
        "provider": settings.get("provider", "gmail"),
        "smtp_host": settings.get("smtp_host", "smtp.gmail.com"),
        "smtp_port": int(settings.get("smtp_port") or 587),
        "use_starttls": bool(settings.get("use_starttls", True)),
        "sender": settings.get("sender", ""),
        "username": settings.get("username") or settings.get("sender", ""),
        "app_password": settings.get("app_password", ""),
        "recipients": normalize_recipients(settings.get("recipients", [])),
        "cooldown_minutes": int(settings.get("cooldown_minutes") or 15),
        "dangerous_only": bool(settings.get("dangerous_only", True)),
        "dashboard_base_url": settings.get("dashboard_base_url", ""),
    }


def normalize_recipients(value):
    if isinstance(value, str):
        parts = value.replace("\n", ",").split(",")
    else:
        parts = value or []
    return [str(item).strip() for item in parts if str(item).strip()]


def sanitized_email_settings(config):
    settings = email_settings(config)
    app_password = email_settings(config).get("app_password", "")
    settings["app_password"] = ""
    settings["app_password_configured"] = bool(app_password)
    settings["app_password_length"] = len(app_password)
    return settings


def notification_cooldown_key(response):
    return "|".join(
        [
            str(response.get("final_classification") or ""),
            str(response.get("target_ip") or ""),
            str(response.get("final_action") or ""),
        ]
    )


def cooldown_active(conn, key, cooldown_minutes):
    if cooldown_minutes <= 0:
        return False
    latest = latest_sent_notification(conn, key)
    if not latest or not latest.get("sent_at"):
        return False
    try:
        sent_at = datetime.fromisoformat(str(latest["sent_at"]))
    except ValueError:
        return False
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    elapsed_minutes = (datetime.now(timezone.utc) - sent_at).total_seconds() / 60
    return elapsed_minutes < cooldown_minutes


def should_notify(settings, response):
    if not settings.get("enabled"):
        return False, "email notifications disabled"
    if not settings.get("sender") or not settings.get("app_password"):
        return False, "Gmail sender or app password not configured"
    if not settings.get("recipients"):
        return False, "no notification recipients configured"
    if settings.get("dangerous_only") and response.get("final_classification") != "Dangerous":
        return False, "not a dangerous decision"
    return True, ""


def dashboard_link(settings, detection_id):
    base_url = (settings.get("dashboard_base_url") or "").rstrip("/")
    if not base_url or not detection_id:
        return ""
    return f"{base_url}/investigation?id={detection_id}"


def build_dangerous_email(settings, alert, detection, response, ai_report):
    detection_name = str(detection.get("detection_type") or "Unknown").replace("_", " ").title()
    subject = f"[Security VM] Dangerous alert: {detection_name} from {alert.get('src_ip', 'unknown')}"
    link = dashboard_link(settings, response.get("detection_id"))
    lines = [
        "Security VM detected a dangerous network event.",
        "",
        f"Classification: {response.get('final_classification', 'Unknown')}",
        f"Score: {response.get('final_score', 'unknown')}/100",
        f"Action: {response.get('final_action', 'unknown')}",
        f"Target IP: {response.get('target_ip', 'unknown')}",
        "",
        f"Source: {alert.get('src_ip', 'unknown')}:{alert.get('src_port', 'unknown')}",
        f"Destination: {alert.get('dest_ip', 'unknown')}:{alert.get('dest_port', 'unknown')}",
        f"Protocol: {alert.get('protocol', 'unknown')}",
        f"Signature: {alert.get('signature', 'unknown')}",
        f"Detection type: {detection_name}",
        "",
        f"AI profile: {ai_report.get('model_identity', 'unknown model')}",
        f"AI confidence: {ai_report.get('confidence', 'unknown')}",
        f"AI reason: {ai_report.get('reason', 'No AI reason stored.')}",
    ]
    if link:
        lines.extend(["", f"Dashboard link: {link}"])
    return subject, "\n".join(lines)


def send_email(settings, subject, body):
    message = EmailMessage()
    message["From"] = settings["sender"]
    message["To"] = ", ".join(settings["recipients"])
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(settings["smtp_host"], settings["smtp_port"], timeout=20) as smtp:
        if settings.get("use_starttls", True):
            smtp.starttls()
        smtp.login(settings["username"] or settings["sender"], settings["app_password"])
        smtp.send_message(message)


def notify_dangerous_decision(conn, config, alert, detection, response, ai_report):
    settings = email_settings(config)
    key = notification_cooldown_key(response)
    ok, reason = should_notify(settings, response)
    if not ok:
        insert_notification_event(
            conn,
            {
                "detection_id": response.get("detection_id"),
                "response_id": response.get("response_id"),
                "channel": "email",
                "recipient": ",".join(settings.get("recipients", [])),
                "subject": "Security VM notification skipped",
                "status": "skipped",
                "error": reason,
                "cooldown_key": key,
            },
        )
        return {"status": "skipped", "reason": reason}

    if cooldown_active(conn, key, settings.get("cooldown_minutes", 15)):
        insert_notification_event(
            conn,
            {
                "detection_id": response.get("detection_id"),
                "response_id": response.get("response_id"),
                "channel": "email",
                "recipient": ",".join(settings["recipients"]),
                "subject": "Security VM notification skipped by cooldown",
                "status": "skipped",
                "error": "cooldown active",
                "cooldown_key": key,
            },
        )
        return {"status": "skipped", "reason": "cooldown active"}

    subject, body = build_dangerous_email(settings, alert, detection, response, ai_report)
    try:
        send_email(settings, subject, body)
        insert_notification_event(
            conn,
            {
                "detection_id": response.get("detection_id"),
                "response_id": response.get("response_id"),
                "channel": "email",
                "recipient": ",".join(settings["recipients"]),
                "subject": subject,
                "status": "sent",
                "cooldown_key": key,
            },
        )
        return {"status": "sent", "subject": subject}
    except Exception as exc:
        insert_notification_event(
            conn,
            {
                "detection_id": response.get("detection_id"),
                "response_id": response.get("response_id"),
                "channel": "email",
                "recipient": ",".join(settings["recipients"]),
                "subject": subject,
                "status": "failed",
                "error": str(exc),
                "cooldown_key": key,
            },
        )
        return {"status": "failed", "error": str(exc)}
