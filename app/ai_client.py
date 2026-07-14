import json
import hashlib
import time

import requests


PROMPT_VERSION = "security-vm-multi-sensor-triage-v3"


def infer_model_provider(host, model):
    text = f"{host or ''} {model or ''}".lower()
    if "nvidia" in text or "nim" in text:
        return "nvidia"
    if "deepseek" in text:
        return "deepseek"
    if "llama" in text or "ollama" in text:
        return "ollama"
    return "ai_service"


def model_metadata(config):
    ai_model = config.get("ai_model", {})
    host = (ai_model.get("host") or "").rstrip("/")
    model = ai_model.get("model", "llama3.1:8b")
    provider = ai_model.get("provider") or infer_model_provider(host, model)
    identity = f"{provider}:{model}"
    profile_uid = ai_model.get("active_profile_uid") or ai_model.get("profile_uid") or legacy_profile_uid(provider, host, model)
    return {
        "ai_profile_uid": profile_uid,
        "model_provider": provider,
        "model_name": model,
        "model_identity": identity,
        "model_endpoint": host,
        "prompt_version": PROMPT_VERSION,
    }


def legacy_profile_uid(provider, host, model):
    seed = f"{provider}|{host}|{model}"
    return f"legacy-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"


def model_run_id(metadata, alert):
    seed = "|".join(
        [
            metadata.get("model_identity", ""),
            metadata.get("ai_profile_uid", ""),
            metadata.get("model_endpoint", ""),
            metadata.get("prompt_version", ""),
            str(time.time_ns()),
            str(alert.get("timestamp") or ""),
            str(alert.get("src_ip") or ""),
            str(alert.get("dest_ip") or ""),
            str(alert.get("signature") or ""),
        ]
    )
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def text_sha256(value):
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def build_prompt(alert, detection, evidence_context=None, pcap_summary=""):
    asset_context = detection.get("asset_context") or {}
    encrypted_ports = {22, 443, 853, 8443, 1194, 500, 4500, 51820}
    signature_text = " ".join(
        str(value or "")
        for value in [alert.get("signature"), alert.get("category"), detection.get("detection_type")]
    ).lower()
    src_port = alert.get("src_port")
    dest_port = alert.get("dest_port")
    try:
        port_values = {int(src_port or 0), int(dest_port or 0)}
    except (TypeError, ValueError):
        port_values = set()
    encrypted_keywords = ["tls", "ssl", "https", "quic", "vpn", "wireguard", "openvpn", "ipsec", "ssh"]
    likely_encrypted = bool(port_values & encrypted_ports) or any(word in signature_text for word in encrypted_keywords)
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
            "sensor_state": detection.get("sensor_state", "suricata_only"),
            "agreement_state": detection.get("agreement_state", "single_sensor"),
            "correlation_method": detection.get("correlation_method", "single_sensor"),
            "correlation_confidence": detection.get("correlation_confidence", 0.5),
            "community_id": detection.get("community_id"),
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
        "encrypted_traffic_context": {
            "likely_encrypted_or_tunneled": likely_encrypted,
            "source_port": src_port,
            "destination_port": dest_port,
            "visible_to_security_vm": [
                "source_ip",
                "destination_ip",
                "ports",
                "protocol",
                "DNS/TLS metadata when present",
                "timing",
                "connection volume",
                "Suricata signatures and Zeek notices",
                "multi-source threat intelligence matches",
                "packet summary metadata",
            ],
            "not_visible_without_endpoint_or_tls_decryption": [
                "encrypted payload contents",
                "full HTTPS URLs after TLS setup",
                "commands inside encrypted sessions",
                "endpoint process names",
                "files or registry changes",
            ],
        },
        "evidence_context": evidence_context or {},
        "pcap_summary": pcap_summary or "No packet-level summary generated for this alert.",
    }

    instructions = """
You are assisting a cybersecurity lab system that triages unified network detections from Suricata and Zeek.
Python already calculated python_initial_score from deterministic rules. Your job is not to replace that score; your job is to provide a bounded second opinion.

Return only valid JSON with exactly these keys:
classification, confidence, risk_adjustment, reason, recommended_action.

Allowed values:
- classification: Safe, Human Review Required, Dangerous
- confidence: Low, Medium, High
- risk_adjustment: integer from -20 to 20
- recommended_action: log_only, human_review, would_block, temporary_block

Scoring guidance:
- Use risk_adjustment to tune Python's score, not to create a new score.
- -20 to -11: strong evidence this is benign, expected, noisy, or normal software behavior.
- -10 to -1: somewhat lower risk than Python estimated.
- 0: Python score looks reasonable, or evidence is insufficient.
- 1 to 10: suspicious context raises risk.
- 11 to 20: strong malicious indicators, high-confidence attack behavior, or critical asset impact.

Classification guidance:
- Safe: likely benign or routine activity. Usually recommend log_only.
- Human Review Required: suspicious, ambiguous, incomplete context, low confidence, or activity involving important assets. Usually recommend human_review.
- Dangerous: high-confidence malicious behavior, clear attack pattern, or severe risk to a high-value asset. Recommend would_block or temporary_block only when confidence is High.

Asset guidance:
- registered_asset_context comes from analyst-defined SQLite inventory.
- asset_score is 0-10. Higher means higher business impact.
- Laptops, servers, routers/firewalls, and security appliances should raise concern when targeted or behaving unusually.
- Do not mark something Dangerous only because asset_score is high; combine asset importance with alert behavior.

Evidence rules:
- sensor_fusion in evidence_context is authoritative about which sensors produced findings. Evaluate every finding independently and then explain whether they support the same security conclusion.
- A Suricata signature may initiate a detection without a Zeek notice. A Zeek notice may initiate a detection without a Suricata signature. Absence of a finding from one sensor is missing evidence, not evidence that the traffic is safe, and must never cancel the other sensor's finding.
- When sensor_state is multi_sensor, use Community ID or flow/time correlation metadata to understand why findings were grouped. Corroborating independent findings should increase confidence, but should not automatically mean Dangerous.
- Compatible findings can describe different layers of the same behavior, such as a Suricata C2 signature plus a Zeek certificate anomaly. Name both sensors and their findings in the reason.
- Treat zeek_context notice rows as policy findings. Treat conn, dns, ssl, http, files, ssh, and x509 rows as supporting metadata. A weird row alone is generally context, not proof of malicious activity.
- If findings are materially inconsistent and the conflict cannot be resolved with threat intelligence, asset context, Zeek metadata, or packet summary evidence, choose Human Review Required and describe the disputed evidence.
- Treat DNS tunneling, port scans, repeated connections, many destination ports, or MITRE-mapped behavior as more suspicious.
- Treat common update traffic, local/private broadcast noise, and known routine client behavior as lower risk unless correlated volume is high.
- Use threat_intel in evidence_context when present. Treat matches from independent sources as corroborating evidence, consider confidence/category/freshness, and name the sources in the reason. No match or an inactive provider does not make an alert safe.
- Use pcap_evidence in evidence_context as supporting context only. Related capture files mean packet data exists for analyst follow-up, but raw packet contents are not included unless a packet_summary is present.
- If encrypted_traffic_context.likely_encrypted_or_tunneled is true, do not claim to inspect decrypted payloads. Reason from observable metadata: source/destination, ports, DNS/TLS hints, timing, volume, reputation, asset context, correlation, and packet summaries.
- For possible VPN/C2 tunnels, raise concern when encrypted traffic is long-lived, repetitive, high-volume, unusual for the asset, uses VPN-like ports, goes to untrusted infrastructure, or has suspicious threat intel. If those signals are absent, prefer Human Review Required or Safe with clear low-confidence wording.
- If context is missing, prefer Human Review Required with Low or Medium confidence instead of guessing.
- The reason must briefly explain the main evidence and why the adjustment was chosen.

Analyze this event package:
"""
    return instructions.strip() + "\n\n" + json.dumps(package, indent=2)


def build_prompt_audit(config, alert, detection, evidence_context=None, pcap_summary=""):
    metadata = model_metadata(config)
    prompt = build_prompt(alert, detection, evidence_context, pcap_summary)
    packet_summary_text = pcap_summary or ""
    return prompt, {
        **metadata,
        "model_run_id": model_run_id(metadata, alert),
        "prompt_sha256": text_sha256(prompt),
        "prompt_chars": len(prompt),
        "pcap_summary_sha256": text_sha256(packet_summary_text) if packet_summary_text else "",
        "pcap_summary_chars": len(packet_summary_text),
        "pcap_summary_included": 1 if packet_summary_text else 0,
    }


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
    parsed["reason"] = normalize_text(parsed.get("reason"), "AI model did not provide a reason.")
    parsed["recommended_action"] = normalize_text(parsed.get("recommended_action"), "human_review")
    return parsed


def ask_ai_model(config, alert, detection, evidence_context=None, pcap_summary=""):
    ai_model = config.get("ai_model", {})
    prompt, audit = build_prompt_audit(config, alert, detection, evidence_context, pcap_summary)
    host = audit["model_endpoint"]
    model = audit["model_name"]
    timeout = ai_model.get("timeout_seconds", 90)
    options = {
        "num_predict": int(ai_model.get("num_predict", 192)),
        "num_ctx": int(ai_model.get("num_ctx", 8192)),
        "temperature": float(ai_model.get("temperature", 0.1)),
    }
    start = time.monotonic()

    response_chunks = []
    with requests.post(
        f"{host}/api/generate",
        json={"model": model, "prompt": prompt, "stream": True, "format": "json", "options": options},
        timeout=timeout,
        stream=True,
    ) as response:
        response.raise_for_status()
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            chunk = json.loads(line)
            if chunk.get("error"):
                raise requests.RequestException(chunk["error"])
            response_chunks.append(chunk.get("response", ""))
            if chunk.get("done"):
                break

    elapsed_ms = int((time.monotonic() - start) * 1000)
    raw_text = "".join(response_chunks) or "{}"

    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        parsed = {
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": "AI model returned non-JSON output.",
            "recommended_action": "human_review",
        }

    parsed = normalize_report(parsed)
    parsed.update(audit)
    parsed["raw_response"] = raw_text
    parsed["elapsed_ms"] = elapsed_ms
    return parsed


def check_ai_model(config):
    ai_model = config.get("ai_model", {})
    metadata = model_metadata(config)
    host = metadata["model_endpoint"]
    timeout = min(int(ai_model.get("timeout_seconds", 90)), 10)
    start = time.monotonic()

    response = requests.get(f"{host}/api/tags", timeout=timeout)
    response.raise_for_status()
    elapsed_ms = int((time.monotonic() - start) * 1000)
    models = [model.get("name") for model in response.json().get("models", [])]
    return {
        **metadata,
        "host": host,
        "elapsed_ms": elapsed_ms,
        "models": models,
    }
