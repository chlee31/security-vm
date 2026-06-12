import json
import time

import requests


def build_prompt(alert, detection, pcap_summary=""):
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
        },
        "pcap_summary": pcap_summary or "No PCAP summary generated for this alert.",
    }

    return (
        "You are assisting a cybersecurity lab system. "
        "Return only valid JSON with keys: classification, confidence, risk_adjustment, "
        "reason, recommended_action. Classifications: Safe, Human Review Required, Dangerous.\n\n"
        + json.dumps(package, indent=2)
    )


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
