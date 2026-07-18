import json
import hashlib
import re
import time

import requests


PROMPT_VERSION = "security-vm-case-explanation-v8-threat-intel"

THREAT_INTEL_PROVIDER_NAMES = (
    "otx",
    "threatfox",
    "urlhaus",
    "sslbl",
    "spamhaus_drop",
    "openphish",
    "ipsum",
    "feodo",
    "virustotal",
)

THREAT_INTEL_PROVIDER_SCHEMA = {
    name: {"type": "string"} for name in THREAT_INTEL_PROVIDER_NAMES
}

AI_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["Safe", "Human Review Required", "Dangerous"],
        },
        "confidence": {"type": "string", "enum": ["Low", "Medium", "High"]},
        "risk_adjustment": {"type": "integer", "minimum": -10, "maximum": 10},
        "reason": {"type": "string"},
        "summary": {"type": "string"},
        "who": {"type": "string"},
        "what": {"type": "string"},
        "when": {"type": "string"},
        "where": {"type": "string"},
        "why": {"type": "string"},
        "how": {"type": "string"},
        "next_steps": {
            "type": "array",
            "minItems": 2,
            "maxItems": 5,
            "items": {"type": "string"},
        },
        "threat_intel_analysis": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "overall": {"type": "string"},
                "influence": {
                    "type": "string",
                    "enum": [
                        "none",
                        "supports_benign",
                        "supports_suspicious",
                        "supports_malicious",
                        "mixed",
                        "unavailable",
                    ],
                },
                "providers": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": THREAT_INTEL_PROVIDER_SCHEMA,
                    "required": list(THREAT_INTEL_PROVIDER_NAMES),
                },
            },
            "required": ["overall", "influence", "providers"],
        },
        "recommended_action": {
            "type": "string",
            "enum": ["log_only", "human_review", "investigate", "escalate"],
        },
    },
    "required": [
        "classification",
        "confidence",
        "risk_adjustment",
        "reason",
        "summary",
        "who",
        "what",
        "when",
        "where",
        "why",
        "how",
        "next_steps",
        "threat_intel_analysis",
        "recommended_action",
    ],
}

OMITTED_AI_EVIDENCE_KEYS = {
    "raw_event",
    "raw_json",
    "raw_data",
    "raw_response",
    "api_key",
    "app_password",
    "password",
    "secret",
    "token",
}


def compact_ai_evidence(value, key="", depth=0):
    if depth > 8:
        return "[nested evidence omitted]"
    if str(key).lower() in OMITTED_AI_EVIDENCE_KEYS:
        return "[raw or sensitive field omitted]"
    if isinstance(value, dict):
        return {
            child_key: compact_ai_evidence(child_value, child_key, depth + 1)
            for child_key, child_value in value.items()
            if str(child_key).lower() not in OMITTED_AI_EVIDENCE_KEYS
        }
    if isinstance(value, list):
        return [compact_ai_evidence(item, key, depth + 1) for item in value[:25]]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + " [truncated by Python]"
    return value


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


def build_prompt(alert, detection, evidence_context=None):
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
            "case_uid": detection.get("case_uid"),
            "src_ip": alert.get("src_ip"),
            "dest_ip": alert.get("dest_ip"),
            "src_port": alert.get("src_port"),
            "dest_port": alert.get("dest_port"),
            "protocol": alert.get("protocol"),
            "signature": alert.get("signature"),
            "first_seen": detection.get("first_seen") or alert.get("timestamp"),
            "last_seen": detection.get("last_seen") or alert.get("timestamp"),
        },
        "correlation": {
            "alert_count": detection.get("alert_count"),
            "unique_destination_ports": detection.get("unique_dest_ports"),
            "time_window_seconds": detection.get("time_window_seconds"),
            "detection_type": detection.get("detection_type"),
            "sensor_state": detection.get("sensor_state", "suricata_only"),
            "agreement_state": detection.get("agreement_state", "single_sensor"),
            "correlation_method": detection.get("correlation_method", "single_sensor"),
            "correlation_rule_strength": detection.get("correlation_confidence", 0.5),
            "community_id": detection.get("community_id"),
            "repeated_activity": (evidence_context or {}).get("repeated_activity", {}),
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
                "sensor-provided connection metadata",
            ],
            "not_visible_without_endpoint_or_tls_decryption": [
                "encrypted payload contents",
                "full HTTPS URLs after TLS setup",
                "commands inside encrypted sessions",
                "endpoint process names",
                "files or registry changes",
            ],
        },
        "evidence_context": compact_ai_evidence(evidence_context or {}),
    }

    instructions = """
You are assisting a cybersecurity lab system that triages unified network detections from Suricata and Zeek.
Python already calculated a deterministic score from six auditable categories with a maximum of 90 points. Your job is not to replace that score; your job is to provide a bounded second opinion.

Return only valid JSON with exactly these keys:
classification, confidence, risk_adjustment, reason, summary, who, what, when, where, why, how, next_steps, threat_intel_analysis, recommended_action.

Allowed values:
- classification: Safe, Human Review Required, Dangerous
- confidence: Low, Medium, High
- risk_adjustment: integer from -10 to 10
- recommended_action: log_only, human_review, investigate, escalate
- reason, summary, who, what, when, where, why, and how: concise strings grounded only in supplied evidence
- next_steps: an ordered array of two to five concrete analyst investigation steps
- threat_intel_analysis: an object containing overall, influence, and providers. providers must contain one concise interpretation for every named source: otx, threatfox, urlhaus, sslbl, spamhaus_drop, openphish, ipsum, feodo, and virustotal.

Scoring guidance:
- Use risk_adjustment to tune Python's score, not to create a new score.
- -10 to -6: strong evidence this is benign, expected, noisy, or normal software behavior.
- -5 to -1: somewhat lower risk than Python estimated.
- 0: Python score looks reasonable, or evidence is insufficient.
- 1 to 10: suspicious context raises risk.
- 6 to 10: strong malicious indicators, high-confidence attack behavior, or critical asset impact.

Classification guidance:
- Safe: likely benign or routine activity. Usually recommend log_only.
- Human Review Required: suspicious, ambiguous, incomplete context, low confidence, or activity involving important assets. Usually recommend human_review.
- Dangerous: high-confidence malicious behavior, clear attack pattern, or severe risk to a high-value asset. Recommend escalate.

Asset guidance:
- registered_asset_context comes from analyst-defined SQLite inventory.
- asset_score is 0-10. Higher means higher business impact.
- Laptops, servers, routers/firewalls, and security appliances should raise concern when targeted or behaving unusually.
- Do not mark something Dangerous only because asset_score is high; combine asset importance with alert behavior.

Evidence rules:
- sensor_fusion in evidence_context is authoritative about which sensors produced findings. Evaluate every finding independently and then explain whether they support the same security conclusion.
- A Suricata signature may initiate a detection without a Zeek notice. A Zeek notice may initiate a detection without a Suricata signature. Absence of a finding from one sensor is missing evidence, not evidence that the traffic is safe, and must never cancel the other sensor's finding.
- When sensor_state is multi_sensor, use Community ID or flow/time correlation metadata to understand why findings were grouped. Corroborating independent findings should increase confidence, but should not automatically mean Dangerous.
- correlation_rule_strength is a configured rule value, not a calibrated probability or model confidence score.
- Compatible findings can describe different layers of the same behavior, such as a Suricata C2 signature plus a Zeek certificate anomaly. Name both sensors and their findings in the reason.
- Treat zeek_context notice rows as policy findings. Treat conn, dns, ssl, http, files, ssh, and x509 rows as supporting metadata. A weird row alone is generally context, not proof of malicious activity.
- If findings are materially inconsistent and the conflict cannot be resolved with threat intelligence, asset context, or Zeek metadata, choose Human Review Required and describe the disputed evidence.
- Treat DNS tunneling, port scans, repeated connections, many destination ports, or MITRE-mapped behavior as more suspicious.
- Treat common update traffic, local/private broadcast noise, and known routine client behavior as lower risk unless correlated volume is high.
- Use threat_intel in evidence_context when present. provider_status describes whether each source was active and refreshed; each observable's providers list describes matched, no_match, not_active, or unavailable results. Treat matches from independent sources as corroborating evidence and consider confidence, category, and freshness.
- In threat_intel_analysis.providers, discuss every provider separately. State "Not active", "No match", or "Unavailable" when that is the supplied state. For matches, name the observable, category, confidence when supplied, and what the match means. Do not turn a no-match result into proof that traffic is benign.
- VirusTotal is post-AI verification. During an initial comparison it will normally be not requested; state that clearly and do not imply it was checked. During reassessment, interpret only the stored VirusTotal evidence supplied by Python.
- The explanation must explicitly cover who, what, when, where, why, and how. Distinguish observed facts from interpretations and uncertainty.
- Make next_steps specific to this case and order them by investigative value. Each step must name the evidence or observable to inspect and what question the analyst should answer. Do not return generic advice such as only "monitor traffic" or "investigate further."
- Good next steps include checking a named Zeek log field, validating a named Suricata signature, reviewing a specific IP/domain/certificate/hash in the supplied threat-intelligence evidence, comparing recurrence within the supplied time window, or validating whether the named registered IP role normally produces this behavior.
- Use repeated_activity and zeek_context.summary to explain recurrence, duration, byte counts, DNS repetition, TLS server names, and periodicity only when those fields contain evidence.
- Do not claim access to packet captures, decrypted payloads, endpoint processes, users, files, or host activity unless the supplied evidence explicitly contains that information.
- If encrypted_traffic_context.likely_encrypted_or_tunneled is true, do not claim to inspect decrypted payloads. Reason from observable metadata: source/destination, ports, DNS/TLS hints, timing, volume, reputation, asset context, correlation, and sensor metadata.
- For possible VPN/C2 tunnels, raise concern when encrypted traffic is long-lived, repetitive, high-volume, unusual for the asset, uses VPN-like ports, goes to untrusted infrastructure, or has suspicious threat intel. If those signals are absent, prefer Human Review Required or Safe with clear low-confidence wording.
- If context is missing, prefer Human Review Required with Low or Medium confidence instead of guessing.
- Do not identify, advertise, or speculate about the model or provider that produced the response. Python records model identity separately.
- The reason must briefly explain the main evidence and why the adjustment was chosen.

Analyze this event package:
"""
    output_reminder = (
        "Return only one JSON object that validates against this exact schema. "
        "Do not copy an input sensor record and do not invent another schema:\n"
        + json.dumps(AI_RESPONSE_SCHEMA, separators=(",", ":"))
    )
    return instructions.strip() + "\n\n" + json.dumps(package, indent=2) + "\n\n" + output_reminder


def build_prompt_audit(config, alert, detection, evidence_context=None):
    metadata = model_metadata(config)
    prompt = build_prompt(alert, detection, evidence_context)
    return prompt, {
        **metadata,
        "model_run_id": model_run_id(metadata, alert),
        "prompt_sha256": text_sha256(prompt),
        "prompt_chars": len(prompt),
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
    return max(-10, min(10, adjustment))


def normalize_text(value, fallback=""):
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def parse_model_response(raw_text):
    """Parse direct, fenced, or prefaced JSON without evaluating model text."""
    text = str(raw_text or "").strip()
    attempts = [text]
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().lower() in {"```", "```json"}:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        attempts.append("\n".join(lines).strip())

    decoder = json.JSONDecoder()
    for candidate in attempts:
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed

        for index, char in enumerate(candidate):
            if char != "{":
                continue
            try:
                parsed, _end = decoder.raw_decode(candidate[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed

    recovered = {}
    scalar_pattern = r'("(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?|true|false|null)'
    for key in (
        "classification",
        "confidence",
        "risk_adjustment",
        "reason",
        "summary",
        "who",
        "what",
        "when",
        "where",
        "why",
        "how",
        "recommended_action",
    ):
        match = re.search(rf'"{key}"\s*:\s*{scalar_pattern}', text, flags=re.IGNORECASE)
        if not match:
            continue
        try:
            recovered[key] = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
    if recovered.get("summary") or len(recovered) >= 3:
        recovered["_partial_response"] = True
        return recovered
    raise ValueError("AI model response did not contain a valid JSON object")


def normalize_confidence(value):
    if isinstance(value, (int, float)):
        if 0 <= value <= 1:
            value *= 100
        if value >= 75:
            return "High"
        if value >= 40:
            return "Medium"
        return "Low"
    text = normalize_text(value, "Low").strip().lower()
    if text in {"high", "medium", "low"}:
        return text.title()
    try:
        return normalize_confidence(float(text.rstrip("%")))
    except ValueError:
        return "Low"


def normalize_report(parsed):
    for wrapper in ("response", "result", "assessment"):
        if isinstance(parsed.get(wrapper), dict):
            parsed = {**parsed, **parsed[wrapper]}
    if isinstance(parsed.get("threat_summary"), dict):
        threat_summary = parsed["threat_summary"]
        risk = parsed.get("risk_assessment") if isinstance(parsed.get("risk_assessment"), dict) else {}
        recommendations = parsed.get("recommendations") if isinstance(parsed.get("recommendations"), list) else []
        mitigation = parsed.get("mitigation_strategy") if isinstance(parsed.get("mitigation_strategy"), dict) else {}
        severity = str(risk.get("severity_level") or "Medium").lower()
        parsed.setdefault(
            "classification",
            "Dangerous" if severity in {"high", "critical", "dangerous"} else "Safe" if severity == "low" else "Human Review Required",
        )
        parsed.setdefault("confidence", risk.get("confidence_score"))
        parsed.setdefault("risk_adjustment", 0)
        parsed.setdefault("summary", threat_summary.get("activity_pattern") or normalize_text(threat_summary))
        parsed.setdefault("who", threat_summary.get("ip_address") or "Endpoints named in the supplied evidence")
        parsed.setdefault("what", threat_summary.get("activity_pattern") or "Network sensor finding")
        parsed.setdefault("when", "During the supplied case window")
        parsed.setdefault("where", threat_summary.get("port_range") or "Network boundary")
        rationales = [item.get("rationale") for item in recommendations if isinstance(item, dict) and item.get("rationale")]
        parsed.setdefault("reason", " ".join(rationales) or normalize_text(risk))
        parsed.setdefault("why", parsed["reason"])
        parsed.setdefault("how", "Correlated network-sensor metadata and threat-intelligence context")
        steps = [item.get("action") for item in recommendations if isinstance(item, dict) and item.get("action")]
        steps.extend(mitigation.get("immediate_actions") or [])
        parsed.setdefault("next_steps", steps)
        parsed.setdefault("recommended_action", "investigate")
    elif parsed.get("event_type") == "alert" or parsed.get("finding_type"):
        alert = parsed.get("alert") if isinstance(parsed.get("alert"), dict) else {}
        parsed = {
            **parsed,
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": "The model echoed a sensor record instead of returning an analytical explanation.",
            "summary": "Invalid analytical response: the model copied normalized sensor evidence.",
            "who": f"{parsed.get('src_ip') or parsed.get('source_ip') or 'unknown source'} to {parsed.get('dest_ip') or parsed.get('destination_ip') or 'unknown destination'}",
            "what": alert.get("signature") or parsed.get("finding_name") or "Sensor finding",
            "when": parsed.get("finding_timestamp") or parsed.get("created_at") or "Supplied case window",
            "where": f"{parsed.get('src_port') or parsed.get('source_port') or '?'} to {parsed.get('dest_port') or parsed.get('destination_port') or '?'}",
            "why": "No model rationale was returned.",
            "how": "The response repeated an input Suricata or Zeek record without analyzing it.",
            "next_steps": [
                "Rerun this comparison using the enforced response schema.",
                "Review the preserved sensor finding directly while awaiting a valid model response.",
            ],
            "recommended_action": "human_review",
        }
    parsed["classification"] = normalize_text(parsed.get("classification"), "Human Review Required")
    parsed["confidence"] = normalize_confidence(parsed.get("confidence"))
    parsed["risk_adjustment"] = normalize_risk_adjustment(parsed.get("risk_adjustment"))
    parsed["reason"] = normalize_text(
        parsed.get("reason") or parsed.get("reasoning") or parsed.get("analysis"),
        "AI model did not provide a reason.",
    )
    parsed["recommended_action"] = normalize_text(parsed.get("recommended_action"), "human_review")
    parsed["summary"] = normalize_text(
        parsed.get("summary") or parsed.get("case_summary"),
        parsed["reason"],
    )
    for key in ("who", "what", "when", "where", "why", "how"):
        parsed[key] = normalize_text(parsed.get(key), "Not established from the supplied evidence.")
    next_steps = (
        parsed.get("next_steps")
        or parsed.get("recommended_next_steps")
        or parsed.get("investigation_steps")
    )
    if isinstance(next_steps, str):
        next_steps = [next_steps]
    elif not isinstance(next_steps, list):
        next_steps = []
    normalized_steps = []
    for item in next_steps:
        if isinstance(item, dict):
            item = item.get("step") or item.get("action") or item.get("description")
        text = normalize_text(item).strip()
        if text:
            normalized_steps.append(text)
    parsed["next_steps"] = normalized_steps[:5]
    if not parsed["next_steps"]:
        parsed["next_steps"] = ["Review the correlated sensor findings and validate the affected asset."]
    threat_intel = parsed.get("threat_intel_analysis")
    if not isinstance(threat_intel, dict):
        threat_intel = {}
    providers = threat_intel.get("providers")
    if not isinstance(providers, dict):
        providers = {}
    normalized_providers = {}
    for name in THREAT_INTEL_PROVIDER_NAMES:
        normalized_providers[name] = normalize_text(
            providers.get(name),
            "The model did not provide a source-specific interpretation.",
        )
    influence = normalize_text(threat_intel.get("influence"), "unavailable").strip().lower()
    allowed_influences = {
        "none",
        "supports_benign",
        "supports_suspicious",
        "supports_malicious",
        "mixed",
        "unavailable",
    }
    if influence not in allowed_influences:
        influence = "unavailable"
    parsed["threat_intel_analysis"] = {
        "overall": normalize_text(
            threat_intel.get("overall"),
            "The model did not provide a dedicated threat-intelligence conclusion.",
        ),
        "influence": influence,
        "providers": normalized_providers,
    }
    allowed_actions = {"log_only", "human_review", "investigate", "escalate"}
    if parsed["recommended_action"] not in allowed_actions:
        parsed["recommended_action"] = "human_review"
    return parsed


def ask_ai_model(config, alert, detection, evidence_context=None):
    ai_model = config.get("ai_model", {})
    prompt, audit = build_prompt_audit(config, alert, detection, evidence_context)
    host = audit["model_endpoint"]
    model = audit["model_name"]
    timeout = ai_model.get("timeout_seconds", 90)
    options = {
        "num_predict": int(ai_model.get("num_predict", 1024)),
        "num_ctx": int(ai_model.get("num_ctx", 8192)),
        "temperature": float(ai_model.get("temperature", 0.1)),
    }
    start = time.monotonic()

    response = requests.post(
        f"{host}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": AI_RESPONSE_SCHEMA,
            "options": options,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    response_payload = response.json()
    if response_payload.get("error"):
        raise requests.RequestException(response_payload["error"])

    elapsed_ms = int((time.monotonic() - start) * 1000)
    raw_text = response_payload.get("response", "") or "{}"

    try:
        parsed = parse_model_response(raw_text)
    except ValueError:
        parsed = {
            "classification": "Human Review Required",
            "confidence": "Low",
            "risk_adjustment": 0,
            "reason": "AI model returned non-JSON output.",
            "recommended_action": "human_review",
            "summary": "The model response could not be parsed.",
            "who": "Not established from the supplied evidence.",
            "what": "The model response could not be parsed.",
            "when": "Not established from the supplied evidence.",
            "where": "Not established from the supplied evidence.",
            "why": "The model did not return valid structured evidence.",
            "how": "Python retained the sensor evidence for human review.",
            "next_steps": ["Review the correlated sensor records manually."],
        }

    partial_response = bool(parsed.pop("_partial_response", False))
    parsed = normalize_report(parsed)
    if partial_response:
        parsed["classification"] = "Human Review Required"
        parsed["confidence"] = "Low"
        parsed["risk_adjustment"] = 0
        parsed["recommended_action"] = "human_review"
        parsed["reason"] = f"Model output was truncated. {parsed['reason']}"
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
