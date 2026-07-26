"""Build, send, validate, and audit requests to an Ollama-compatible AI service.

This module is the boundary between Security VM's trusted Python pipeline and an
external language model. Python, not the model, decides which evidence is
included, removes sensitive/raw fields, enforces size limits, records hashes,
and validates the returned structure.

High-level request path:

1. ``_build_prompt_components`` creates a normalized evidence package.
2. ``build_prompt_audit`` records the exact prompt, package, lineage, and hashes.
3. ``ask_ai_model`` sends that prompt to ``POST /api/generate`` with an explicit
   context window and JSON Schema.
4. ``parse_model_response`` and ``normalize_report`` convert imperfect model
   output into the application's stable qualitative report format.

No files are uploaded to the model. Sensor rows and enrichment records are read
locally, converted to bounded JSON text, and embedded in a single prompt.
"""

import json
import hashlib
import re
import time
import requests


# Stored with every request so a report can identify the exact instruction set
# under which it was produced.
PROMPT_VERSION = "security-vm-case-explanation-v11-qualitative-evidence"
REVIEW_CLASSIFICATION = "Analyst Review Required"

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

# Ollama accepts a JSON Schema in the ``format`` request field. This schema
# narrows the model's output to fields the dashboard and audit trail understand.
AI_RESPONSE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["Safe", REVIEW_CLASSIFICATION, "Dangerous"],
        },
        "confidence": {"type": "string", "enum": ["Low", "Medium", "High"]},
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
        "evidence_review": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "received_sections": {
                    "type": "array",
                    "maxItems": 16,
                    "items": {"type": "string"},
                },
                "evidence_used": {
                    "type": "array",
                    "maxItems": 12,
                    "items": {"type": "string"},
                },
                "missing_or_ambiguous": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {"type": "string"},
                },
                "review_method": {"type": "string"},
            },
            "required": [
                "received_sections",
                "evidence_used",
                "missing_or_ambiguous",
                "review_method",
            ],
        },
        "recommended_action": {
            "type": "string",
            "enum": ["log_only", "human_review", "investigate", "escalate"],
        },
    },
    "required": [
        "classification",
        "confidence",
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
        "evidence_review",
        "recommended_action",
    ],
}

# These keys are never copied into the model prompt. Raw records remain in
# SQLite for analyst review, credentials remain local, and retired score fields
# are excluded from the qualitative workflow.
OMITTED_AI_EVIDENCE_KEYS = {
    "raw_event",
    "raw_json",
    "raw_data",
    "raw_response",
    "raw_record",
    "raw_sensor_json",
    "api_key",
    "app_password",
    "password",
    "secret",
    "token",
    "asset_score",
    "python_initial_score",
    "final_score",
    "risk_adjustment",
    "ai_risk_adjustment",
    "analyst_score",
    "original_score",
    "score_breakdowns",
}


def _compact_ai_evidence(value, key="", path="$", depth=0, omissions=None):
    """Recursively produce a bounded, prompt-safe copy of evidence.

    The function applies three independent controls:

    * sensitive/raw keys are omitted;
    * nesting is capped at eight levels;
    * lists and strings are capped at 25 items and 2,000 characters.

    Every exclusion is added to ``omissions`` so truncation is visible in the
    audit record instead of silently changing what the model receives.
    """
    omissions = omissions if omissions is not None else []
    if depth > 8:
        omissions.append({"path": path, "reason": "maximum_nesting_depth", "limit": 8})
        return "[nested evidence omitted]"
    if str(key).lower() in OMITTED_AI_EVIDENCE_KEYS:
        omissions.append({"path": path, "reason": "raw_or_sensitive_field"})
        return "[raw or sensitive field omitted]"
    if isinstance(value, dict):
        result = {}
        for child_key, child_value in value.items():
            child_path = f"{path}.{child_key}"
            if str(child_key).lower() in OMITTED_AI_EVIDENCE_KEYS:
                omissions.append({"path": child_path, "reason": "raw_or_sensitive_field"})
                continue
            result[child_key] = _compact_ai_evidence(
                child_value, child_key, child_path, depth + 1, omissions
            )
        return result
    if isinstance(value, list):
        if len(value) > 25:
            omissions.append(
                {
                    "path": path,
                    "reason": "list_item_limit",
                    "original_count": len(value),
                    "included_count": 25,
                }
            )
        return [
            _compact_ai_evidence(item, key, f"{path}[{index}]", depth + 1, omissions)
            for index, item in enumerate(value[:25])
        ]
    if isinstance(value, str) and len(value) > 2000:
        omissions.append(
            {
                "path": path,
                "reason": "string_character_limit",
                "original_chars": len(value),
                "included_chars": 2000,
            }
        )
        return value[:2000] + " [truncated by Python]"
    return value


def compact_ai_evidence(value, key="", depth=0):
    """Return bounded evidence when the caller does not need an audit manifest."""
    return _compact_ai_evidence(value, key=key, depth=depth, omissions=[])


def compact_ai_evidence_with_manifest(value, key="", path="$", depth=0):
    """Return both bounded evidence and a list describing every omission."""
    omissions = []
    compacted = _compact_ai_evidence(value, key, path, depth, omissions)
    return compacted, omissions


def infer_model_provider(host, model):
    """Derive a display/provider label from the configured endpoint and model."""
    text = f"{host or ''} {model or ''}".lower()
    if "nvidia" in text or "nim" in text:
        return "nvidia"
    if "deepseek" in text:
        return "deepseek"
    if "llama" in text or "ollama" in text:
        return "ollama"
    return "ai_service"


def model_metadata(config):
    """Return stable identity fields stamped into every AI report and audit."""
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
    """Create a deterministic profile ID for configurations predating profiles."""
    seed = f"{provider}|{host}|{model}"
    return f"legacy-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12]}"


def model_run_id(metadata, alert):
    """Create a unique ID for one model invocation.

    Time is included so repeated assessments of the same case remain separate,
    while model/profile/event fields preserve useful provenance.
    """
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
    """Hash text exactly as Python saw it for later integrity comparison."""
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _evidence_source_map(package):
    """Map normalized prompt sections back to their SQLite source records.

    This lineage is stored locally for auditability; it is not an instruction
    for the model and does not replace the original sensor records.
    """
    evidence = package.get("evidence_context") or {}
    findings = (evidence.get("sensor_fusion") or {}).get("findings") or []
    zeek_items = (evidence.get("zeek_context") or {}).get("items") or []
    intel_records = []

    def collect_intel(value, path):
        if isinstance(value, dict):
            indicator = value.get("indicator")
            for match in value.get("matches") or []:
                if not isinstance(match, dict):
                    continue
                intel_records.append(
                    {
                        "evidence_path": path,
                        "indicator": indicator or match.get("indicator"),
                        "provider": match.get("source") or value.get("name"),
                        "source_table": match.get("source_table") or "threat_intel_indicators",
                        "source_record_id": match.get("source_record_id"),
                    }
                )
            for key, child in value.items():
                collect_intel(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                collect_intel(child, f"{path}[{index}]")

    collect_intel(evidence.get("threat_intel") or {}, "evidence_context.threat_intel")
    return {
        "event_context": {
            "source": "alerts joined to detections",
            "case_uid": (package.get("event_context") or {}).get("case_uid"),
            "event_uid": (package.get("event_context") or {}).get("event_uid"),
            "fields": [
                "src_ip", "dest_ip", "src_port", "dest_port", "protocol",
                "signature", "first_seen", "last_seen",
            ],
        },
        "sensor_fusion.findings": [
            {
                "sensor": item.get("sensor"),
                "source_table": item.get("source_table"),
                "source_record_id": item.get("sensor_event_id"),
                "event_uid": item.get("event_uid"),
                "raw_record_sha256": item.get("raw_record_sha256"),
            }
            for item in findings
        ],
        "zeek_context.items": [
            {
                "source_table": "zeek_events",
                "source_record_id": item.get("id"),
                "event_uid": item.get("event_uid"),
                "zeek_uid": item.get("zeek_uid"),
                "log_type": item.get("log_type"),
            }
            for item in zeek_items
        ],
        "threat_intel": {
            "source": "threat_intel_sources, threat_intel_indicators, threat_intel_lookups, and threat_intel_usage",
            "matched_records": intel_records,
        },
        "registered_ip_role_context": {"source": "registered IP role records in assets"},
    }


def _build_prompt_components(alert, detection, evidence_context=None):
    """Construct the exact prompt and its independently auditable components.

    The prompt has three parts:

    1. fixed analytical and safety instructions;
    2. a normalized JSON evidence package built from the current case; and
    3. a JSON Schema reminder defining the only accepted response shape.

    Returns the final text plus the package, omission manifest, and source map
    so the database can prove what was sent and where each value originated.
    """
    asset_context = detection.get("asset_context") or {}
    role_fields = ("ip_address", "name", "device_type", "network_interface", "function", "notes")

    def role_context(value):
        if not isinstance(value, dict):
            return None
        return {key: value.get(key) for key in role_fields if value.get(key) not in (None, "")}

    # Encryption is inferred only to set visibility expectations. It never
    # claims that payload decryption occurred.
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
    # This is the normalized case package embedded verbatim as JSON in the
    # prompt. It contains selected fields, not raw database or sensor files.
    package = {
        "event_context": {
            "case_uid": detection.get("case_uid"),
            "event_uid": alert.get("event_uid"),
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
        "registered_ip_role_context": {
            "match": asset_context.get("asset_match", "none"),
            "source_ip_role": role_context(asset_context.get("src_asset")),
            "destination_ip_role": role_context(asset_context.get("dest_asset")),
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
        "evidence_context": None,
    }
    # Evidence collected by main.py is filtered at the final trust boundary.
    package["evidence_context"], omissions = compact_ai_evidence_with_manifest(
        evidence_context or {}, key="evidence_context", path="$.evidence_context"
    )

    # The instruction block explains how each evidence type may and may not be
    # interpreted. Keeping it versioned makes model comparisons reproducible.
    instructions = """
You are assisting a cybersecurity lab system that reviews unified network detections from Suricata and Zeek.
Analyze the supplied evidence qualitatively. Do not calculate, infer, or return a numerical risk score, point value, probability, or score adjustment.

Return only valid JSON with exactly these keys:
classification, confidence, reason, summary, who, what, when, where, why, how, next_steps, threat_intel_analysis, evidence_review, recommended_action.

Allowed values:
- classification: Safe, Analyst Review Required, Dangerous
- confidence: Low, Medium, High
- recommended_action: log_only, human_review, investigate, escalate
- reason, summary, who, what, when, where, why, and how: concise strings grounded only in supplied evidence
- next_steps: an ordered array of two to five concrete analyst investigation steps
- threat_intel_analysis: an object containing overall, influence, and providers. providers must contain one concise interpretation for every named source: otx, threatfox, urlhaus, sslbl, spamhaus_drop, openphish, ipsum, feodo, and virustotal.
- evidence_review: identify the supplied top-level sections, the specific records or fields used, missing or ambiguous evidence, and the method used to reach the conclusion. This is a model acknowledgement; Python independently preserves the authoritative request record.

Classification guidance:
- Safe: evidence supports benign or routine activity with Medium or High confidence. Usually recommend log_only.
- Analyst Review Required: suspicious, ambiguous, incomplete context, Low confidence, or activity involving important assets. Usually recommend human_review.
- Dangerous: high-confidence malicious behavior, clear attack pattern, or severe risk to a high-value asset. Recommend escalate.
- A Low-confidence conclusion must always be Analyst Review Required. Never return Safe or Dangerous with Low confidence.

Asset guidance:
- registered_ip_role_context comes from analyst-defined SQLite inventory.
- Use the registered name, device type, function, interface, and notes as descriptive business context.
- A registered role may affect what behavior is expected, but it is not a numerical input and cannot prove maliciousness by itself.

Evidence rules:
- sensor_fusion in evidence_context is authoritative about which sensors produced findings. Evaluate every finding independently and then explain whether they support the same security conclusion.
- A Suricata signature may initiate a detection without a Zeek notice. A Zeek notice may initiate a detection without a Suricata signature. Absence of a finding from one sensor is missing evidence, not evidence that the traffic is safe, and must never cancel the other sensor's finding.
- When sensor_state is multi_sensor, use Community ID or flow/time correlation metadata to understand why findings were grouped. Corroborating independent findings should increase confidence, but should not automatically mean Dangerous.
- correlation_rule_strength is a configured matching value, not a calibrated probability, risk score, or model confidence.
- Compatible findings can describe different layers of the same behavior, such as a Suricata C2 signature plus a Zeek certificate anomaly. Name both sensors and their findings in the reason.
- Treat zeek_context notice rows as policy findings. Treat conn, dns, ssl, http, files, ssh, and x509 rows as supporting metadata. A weird row alone is generally context, not proof of malicious activity.
- If findings are materially inconsistent and the conflict cannot be resolved with threat intelligence, asset context, or Zeek metadata, choose Analyst Review Required and describe the disputed evidence.
- Treat observed DNS tunneling, port scans, repeated connections, or many destination ports according to the supplied sensor evidence.
- Treat common update traffic, local/private broadcast noise, and known routine client behavior as lower risk unless correlated volume is high.
- Use threat_intel in evidence_context when present. provider_status describes whether each source was active and refreshed; each observable's providers list describes matched, no_match, not_active, or unavailable results. Treat matches from independent sources as corroborating evidence and consider confidence, category, and freshness.
- In threat_intel_analysis.providers, discuss every provider separately. State "Not active", "No match", or "Unavailable" when that is the supplied state. For matches, name the observable, category, confidence when supplied, and what the match means. Do not turn a no-match result into proof that traffic is benign.
- VirusTotal is post-AI verification. During an initial comparison it will normally be not requested; state that clearly and do not imply it was checked. During reassessment, interpret only the stored VirusTotal evidence supplied by Python.
- The explanation must explicitly cover who, what, when, where, why, and how. Distinguish observed facts from interpretations and uncertainty.
- Make next_steps specific to this case and order them by investigative value. Each step must name the evidence or observable to inspect and what question the analyst should answer. Do not return generic advice such as only "monitor traffic" or "investigate further."
- Good next steps include checking a named Zeek log field, validating a named Suricata signature, reviewing a specific IP/domain/certificate/hash in the supplied threat-intelligence evidence, comparing recurrence within the supplied time window, or validating whether the named registered IP role normally produces this behavior.
- Use repeated_activity and zeek_context.summary to explain recurrence, duration, byte counts, DNS repetition, TLS server names, and periodicity only when those fields contain evidence.
- Do not claim access to decrypted payloads, endpoint processes, users, files, or host activity unless the supplied evidence explicitly contains that information.
- If encrypted_traffic_context.likely_encrypted_or_tunneled is true, do not claim to inspect decrypted payloads. Reason from observable metadata: source/destination, ports, DNS/TLS hints, timing, volume, reputation, asset context, correlation, and sensor metadata.
- For possible VPN/C2 tunnels, raise concern when encrypted traffic is long-lived, repetitive, high-volume, unusual for the asset, uses VPN-like ports, goes to untrusted infrastructure, or has suspicious threat intel. If those signals are absent but uncertainty remains, prefer Analyst Review Required. Use Safe only when supplied evidence supports routine activity with at least Medium confidence.
- If context is missing, prefer Analyst Review Required with Low or Medium confidence instead of guessing.
- Do not identify, advertise, or speculate about the model or provider that produced the response. Python records model identity separately.
- The reason must briefly explain the main evidence supporting the classification.
- In evidence_review.received_sections, list only section names that are actually present in the event package. In evidence_used, cite concrete event UIDs, Zeek log types, fields, and observables. Do not claim to have received raw sensor JSON because Python deliberately retains raw records locally.

Analyze this event package:
"""
    # Repeating the schema after the evidence reduces the chance that a model
    # returns prose, copies a sensor row, or invents fields.
    output_reminder = (
        "Return only one JSON object that validates against this exact schema. "
        "Do not copy an input sensor record and do not invent another schema:\n"
        + json.dumps(AI_RESPONSE_SCHEMA, separators=(",", ":"))
    )
    # The HTTP request contains this string as ``prompt``. There is no uploaded
    # JSON file; the serialized package is text inside this one request.
    prompt = (
        instructions.strip()
        + "\n\n"
        + json.dumps(package, separators=(",", ":"))
        + "\n\n"
        + output_reminder
    )
    return prompt, package, omissions, _evidence_source_map(package)


def build_prompt(alert, detection, evidence_context=None):
    """Build only the final prompt text for callers that do not need auditing."""
    prompt, _package, _omissions, _source_map = _build_prompt_components(
        alert, detection, evidence_context
    )
    return prompt


def build_prompt_audit(config, alert, detection, evidence_context=None):
    """Build the prompt and the local proof record prepared before transmission.

    Character/byte counts and SHA-256 hashes prove the exact payload. They are
    not token counts. The model server's ``prompt_eval_count``, when returned,
    is the authoritative count of tokens actually evaluated.
    """
    metadata = model_metadata(config)
    prompt, package, omissions, source_map = _build_prompt_components(
        alert, detection, evidence_context
    )
    package_text = json.dumps(package, sort_keys=True, separators=(",", ":"))
    return prompt, {
        **metadata,
        "model_run_id": model_run_id(metadata, alert),
        "prompt_sha256": text_sha256(prompt),
        "prompt_chars": len(prompt),
        "audit_prompt_text": prompt,
        "audit_prompt_bytes": len(prompt.encode("utf-8")),
        "audit_evidence_package": package,
        "audit_evidence_sha256": text_sha256(package_text),
        "audit_evidence_chars": len(package_text),
        "audit_evidence_bytes": len(package_text.encode("utf-8")),
        "audit_evidence_manifest": {
            "top_level_sections": list(package),
            "sensor_finding_count": len(
                ((package.get("evidence_context") or {}).get("sensor_fusion") or {}).get("findings") or []
            ),
            "zeek_context_count": len(
                ((package.get("evidence_context") or {}).get("zeek_context") or {}).get("items") or []
            ),
            "omission_count": len(omissions),
        },
        "audit_omissions": omissions,
        "audit_source_map": source_map,
        "audit_status": "prepared",
    }


def normalize_text(value, fallback=""):
    """Convert optional or structured values into stable displayable text."""
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def parse_model_response(raw_text):
    """Parse direct, fenced, or prefaced JSON without executing model text.

    Strict JSON is attempted first. A bounded recovery pass handles models that
    add Markdown fences or a short preface. If only several scalar fields can be
    recovered, the response is marked partial and later forced to analyst review.
    """
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
    """Normalize legacy numeric or current text confidence to Low/Medium/High."""
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


def normalize_classification(value):
    """Map legacy and current review labels to the canonical analyst label."""
    text = normalize_text(value, REVIEW_CLASSIFICATION).strip().lower().replace("_", " ")
    if text == "safe":
        return "Safe"
    if text == "dangerous":
        return "Dangerous"
    if text in {
        "analyst review",
        "analyst review required",
        "human review",
        "human review required",
        "review",
    }:
        return REVIEW_CLASSIFICATION
    return REVIEW_CLASSIFICATION


def normalize_report(parsed):
    """Convert supported model response variants into one qualitative contract.

    Compatibility branches accept older model formats, but operational scoring
    fields are discarded. Missing sections receive explicit fallback text so
    downstream code never treats absent model output as verified evidence.
    """
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
            "Dangerous" if severity in {"high", "critical", "dangerous"} else "Safe" if severity == "low" else REVIEW_CLASSIFICATION,
        )
        parsed.setdefault("confidence", risk.get("confidence_score"))
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
            "classification": REVIEW_CLASSIFICATION,
            "confidence": "Low",
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
    parsed["classification"] = normalize_classification(parsed.get("classification"))
    parsed["confidence"] = normalize_confidence(parsed.get("confidence"))
    parsed.pop("risk_adjustment", None)
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
    evidence_review = parsed.get("evidence_review")
    if not isinstance(evidence_review, dict):
        evidence_review = {}

    def text_list(value):
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        return [normalize_text(item).strip() for item in value if normalize_text(item).strip()]

    parsed["evidence_review"] = {
        "received_sections": text_list(evidence_review.get("received_sections"))[:16],
        "evidence_used": text_list(evidence_review.get("evidence_used"))[:12],
        "missing_or_ambiguous": text_list(evidence_review.get("missing_or_ambiguous"))[:8],
        "review_method": normalize_text(
            evidence_review.get("review_method"),
            "The model did not return an evidence-review acknowledgement.",
        ),
    }
    allowed_actions = {"log_only", "human_review", "investigate", "escalate"}
    if parsed["recommended_action"] not in allowed_actions:
        parsed["recommended_action"] = "human_review"
    if parsed["confidence"] == "Low":
        parsed["classification"] = REVIEW_CLASSIFICATION
        parsed["recommended_action"] = "human_review"
    return parsed


class AIModelRequestError(requests.RequestException):
    """Request failure that retains the exact local audit record."""

    def __init__(self, message, audit):
        super().__init__(message)
        self.audit = audit


def ask_ai_model(config, alert, detection, evidence_context=None):
    """Send one audited request and return a normalized qualitative report.

    ``num_ctx`` is the total token window allocated by Ollama for this request.
    ``num_predict`` is the maximum generated output within that same window.
    Their difference is therefore the approximate input budget. Security VM
    supplies both values explicitly, so they apply even when the remote Ollama
    app has a different default context-length slider.
    """
    ai_model = config.get("ai_model", {})
    prompt, audit = build_prompt_audit(config, alert, detection, evidence_context)
    host = audit["model_endpoint"]
    model = audit["model_name"]
    timeout = ai_model.get("timeout_seconds", 90)
    # These per-request options are sent to Ollama and take precedence over its
    # server/app defaults for this invocation.
    options = {
        "num_predict": int(ai_model.get("num_predict", 1024)),
        "num_ctx": int(ai_model.get("num_ctx", 8192)),
        "temperature": float(ai_model.get("temperature", 0.1)),
    }
    # Four characters per token is only a planning estimate. Tokenization is
    # model-specific, so prompt_eval_count from Ollama is saved after completion
    # as the measured input count.
    estimated_prompt_tokens = (len(prompt) + 3) // 4
    estimated_input_budget = max(0, options["num_ctx"] - options["num_predict"])
    audit["audit_request_options"] = {
        "transport": "POST /api/generate",
        "stream": False,
        "structured_output": True,
        "response_schema_sha256": text_sha256(
            json.dumps(AI_RESPONSE_SCHEMA, sort_keys=True, separators=(",", ":"))
        ),
        "options": options,
        "timeout_seconds": timeout,
        "estimated_prompt_tokens": estimated_prompt_tokens,
        "estimated_available_input_tokens": estimated_input_budget,
        "estimated_fits_configured_context": estimated_prompt_tokens <= estimated_input_budget,
        "token_estimate_note": "Character-based estimate only; prompt_eval_count is the model-server measurement when returned.",
    }
    start = time.monotonic()
    try:
        # Tailscale, when used, only transports this ordinary HTTP request to the
        # configured host. It does not alter the prompt, schema, or token limits.
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
    except (requests.RequestException, ValueError) as exc:
        audit["audit_status"] = "failed"
        audit["audit_parse_status"] = "request_failed"
        audit["audit_parse_error"] = f"{type(exc).__name__}: {exc}"
        raise AIModelRequestError(str(exc), audit) from exc

    elapsed_ms = int((time.monotonic() - start) * 1000)
    raw_text = response_payload.get("response", "") or "{}"

    # A malformed model response cannot silently become Safe or Dangerous.
    # Parsing failure produces a conservative analyst-review report.
    parse_error = None
    try:
        parsed = parse_model_response(raw_text)
        parse_status = "partial_recovery" if parsed.get("_partial_response") else "valid_json"
    except ValueError as exc:
        parse_status = "fallback"
        parse_error = str(exc)
        parsed = {
            "classification": REVIEW_CLASSIFICATION,
            "confidence": "Low",
            "reason": "AI model returned non-JSON output.",
            "recommended_action": "human_review",
            "summary": "The model response could not be parsed.",
            "who": "Not established from the supplied evidence.",
            "what": "The model response could not be parsed.",
            "when": "Not established from the supplied evidence.",
            "where": "Not established from the supplied evidence.",
            "why": "The model did not return valid structured evidence.",
            "how": "Python retained the sensor evidence for analyst review.",
            "next_steps": ["Review the correlated sensor records manually."],
        }

    partial_response = bool(parsed.pop("_partial_response", False))
    parsed = normalize_report(parsed)
    if partial_response:
        parsed["classification"] = REVIEW_CLASSIFICATION
        parsed["confidence"] = "Low"
        parsed["recommended_action"] = "human_review"
        parsed["reason"] = f"Model output was truncated. {parsed['reason']}"
    parsed.update(audit)
    parsed["raw_response"] = raw_text
    parsed["elapsed_ms"] = elapsed_ms
    parsed["audit_response_sha256"] = text_sha256(raw_text)
    parsed["audit_response_chars"] = len(raw_text)
    parsed["audit_response_bytes"] = len(raw_text.encode("utf-8"))
    parsed["audit_parse_status"] = parse_status
    parsed["audit_parse_error"] = parse_error
    # Ollama's counters provide measured model-server usage. In particular,
    # prompt_eval_count is stronger evidence than Python's character estimate.
    parsed["audit_response_metrics"] = {
        key: response_payload.get(key)
        for key in (
            "done",
            "done_reason",
            "total_duration",
            "load_duration",
            "prompt_eval_count",
            "prompt_eval_duration",
            "eval_count",
            "eval_duration",
        )
        if response_payload.get(key) is not None
    }
    parsed["audit_status"] = "complete"
    return parsed


def check_ai_model(config):
    """Test endpoint reachability and list models without sending case evidence."""
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
