import json
import time

import requests


def build_prompt(alert, detection, pcap_summary=""):
    asset_context = detection.get("asset_context") or {}
    package = {
        "event_context": {
            "src_ip": alert.get("src_ip"),
            "dest_ip": alert.get("dest_ip"),
            "protocol": alert.get("protocol"),
            "signature": alert.get("signature"),
            "timestamp": alert.get("timestamp"),
        },
        "correlation": {
            "alert_count": detection.get("alert_count"),
            "unique_destination_ports": detection.get("unique_dest_ports"),
            "time_window_seconds": detection.get("time_window_seconds"),
            "detection_type": detection.get("detection_type"),
        },
        "mitre_mapping": {
            "technique_id": detection.get("mitre_id"),
            "technique_name": detection.get("mitre_name"),
        },
        "risk_score": {
            "python_initial_score": detection.get("python_initial_score"),
            "asset_score_applied": detection.get("asset_score_applied", 0),
        },
        "registered_asset_context": {
            "match": asset_context.get("asset_match", "none"),
            "asset_score": asset_context.get("asset_score", 0),
            "src_asset": asset_context.get("src_asset"),
            "dest_asset": asset_context.get("dest_asset"),
        },
        "pcap_summary": pcap_summary or "No PCAP summary generated for this alert.",
    }

    return (
        "You are assisting a cybersecurity lab system. "
        "The registered_asset_context is analyst-defined inventory from SQLite; treat a higher asset_score "
        "as higher business impact, especially for servers, laptops, routers, and security appliances. "
        "Return only valid JSON with keys: classification, confidence, risk_adjustment, "
        "reason, recommended_action. Classifications: Safe, Human Review Required, Dangerous. "
        "Confidence must be Low, Medium, or High. "
        "risk_adjustment must be an integer from -20 to 20, not a label or phrase.\n\n"
        + json.dumps(package, indent=2)
    )


def normalize_risk_adjustment(value):
    try:
        adjustment = int(value)
    except (TypeError, ValueError):
        text = str(value or "").lower()
        if "high" in text or "danger" in text or "severe" in text:
            adjustment = 10
        elif "medium" in text or "moderate" in text:
            adjustment = 5
        elif "low" in text or "safe" in text:
            adjustment = 0
        else:
            adjustment = 0
    return max(-20, min(20, adjustment))


def normalize_text(value, fallback=""):
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def normalize_report(parsed):
    parsed["classification"] = normalize_text(parsed.get("classification"), "Human Review Required")
    parsed["confidence"] = normalize_text(parsed.get("confidence"), "Low")
    parsed["risk_adjustment"] = normalize_risk_adjustment(parsed.get("risk_adjustment"))
    parsed["reason"] = normalize_text(parsed.get("reason"), "Ollama did not provide a reason.")
    parsed["recommended_action"] = normalize_text(parsed.get("recommended_action"), "human_review")
    return parsed


def ask_ollama(config, alert, detection, pcap_summary=""):
    ollama = config.get("ollama", {})
    host = ollama.get("host")
    model = ollama.get("model", "llama3.2:latest")
    timeout = ollama.get("timeout_seconds", 90)
    prompt = build_prompt(alert, detection, pcap_summary)
    start = time.monotonic()

    response = requests.post(
        f"{host}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
        timeout=timeout,
    )
    response.raise_for_status()
    elapsed_ms = int((time.monotonic() - start) * 1000)
    raw_text = response.json().get("response", "{}")

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": "Ollama returned non-JSON output.",
            "recommended_action": "human_review",
        }

    parsed = normalize_report(parsed)
    parsed["raw_response"] = raw_text
    parsed["elapsed_ms"] = elapsed_ms
    return parsed


def check_ollama(config):
    ollama = config.get("ollama", {})
    host = ollama.get("host")
    timeout = min(int(ollama.get("timeout_seconds", 90)), 10)
    start = time.monotonic()

    response = requests.get(f"{host}/api/tags", timeout=timeout)
    response.raise_for_status()
    elapsed_ms = int((time.monotonic() - start) * 1000)
    models = [model.get("name") for model in response.json().get("models", [])]
    return {
        "host": host,
        "elapsed_ms": elapsed_ms,
        "models": models,
    }
