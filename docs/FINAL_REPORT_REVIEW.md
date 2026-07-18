# Final Report Implementation Review

Reviewed against the current `dev` implementation on July 17, 2026.

## Overall Assessment

The report has a strong and defensible direction. Its main argument matches the implemented system: Security VM is a passive, out-of-band network investigation assistant that combines Suricata and Zeek evidence, performs deterministic normalization and correlation in Python, enriches public observables with threat intelligence, and uses locally hosted AI to explain evidence for a human reviewer.

The draft should be revised in the areas below before submission. These are primarily factual and methodological clarifications rather than changes to the central research question.

## Claims Confirmed by the Implementation

- Suricata and Zeek are both required data sources at runtime.
- Suricata alerts and Zeek records receive stable event identifiers and are attached to stable case identifiers.
- Correlation can use Community ID, Zeek UID, flow and time proximity, shared observables, and repeated behavior.
- Original sensor JSON is retained alongside normalized records in SQLite.
- The dashboard presents combined findings, correlation context, threat-intelligence evidence, AI explanations, and analyst feedback.
- Cached and bulk threat-intelligence providers are evaluated before AI processing.
- VirusTotal is separate post-AI verification for a Dangerous AI classification and contributes no numerical points.
- Python calculates the deterministic score and retains final control over the stored outcome.
- AI adjustment is bounded to `-10` through `+10`.
- Raw PCAP data and API credentials are not sent to the AI model.
- The evaluated analysis workflow does not automatically block, contain, or close cases.
- The system does not claim endpoint visibility or TLS payload decryption.
- Three active AI profiles can receive the same frozen case evidence sequentially. Their candidate answers do not replace the official case assessment.

## Required Report Corrections

### 1. Use the Current Asset Terminology

Replace **asset inventory** with **registered IP role context**, **registered machine context**, or **analyst-defined IP context**. The current interface keeps a small list of internal IP addresses, names, roles, importance values, and notes in the Admin page. It does not provide a separate enterprise asset-inventory application or endpoint coverage.

Suggested objective wording:

> The system enriches cases with analyst-defined context for registered internal IP addresses, including machine name, role, business function, importance, and notes. This context supports prioritization but does not establish maliciousness or endpoint state.

The internal SQLite table may retain its historical `assets` name for migration compatibility; the report should describe the user-facing capability rather than the table name.

### 2. Correct the Bootstrap Description

The current bootstrap:

- checks the operating system and recommends Ubuntu 22.04 or newer for the tested Zeek path;
- validates or assists with required tools;
- requires Zeek and asks for its monitoring interface;
- can configure Zeek JSON logging and matching Community ID policies;
- initializes or migrates SQLite;
- collects AI service settings; and
- offers an explicitly optional, lab-only router setup helper.

The report should not claim that bootstrap currently asks for internal network ranges, configures the Suricata capture interface, creates the managed-switch mirror session, or collects every threat-intelligence key. Suricata interface/rule configuration and SPAN setup remain administrator tasks. Threat-intelligence providers and credentials are managed through Admin controls.

Replace **Configure the Ollama endpoint** with **Configure the AI model service endpoint and model profile**. Ollama is one compatible runtime, but the application intentionally uses provider-neutral AI terminology.

### 3. Separate Passive Deployment from the Lab Router Helper

The evaluated architecture is passive and should remain the report's primary deployment model. An optional bootstrap helper can configure a laboratory host as a router by changing netplan, IP forwarding, and firewalld NAT settings. That helper is not part of the evaluated passive monitoring workflow.

Suggested boundary wording:

> The analysis pipeline does not enforce firewall actions or alter production traffic. An optional router-configuration helper exists for isolated laboratory testing, but it is excluded from the evaluated passive deployment and should not be enabled on the monitored business network.

### 4. Correct Ingestion Checkpoint Wording

Zeek ingestion stores per-log file, inode, and byte-offset checkpoints. Suricata currently follows new EVE JSON records from the end of the file and relies on database uniqueness to prevent duplicate stored alerts; it does not persist an equivalent EVE byte-offset checkpoint. Do not state that every ingestion process resumes from a stored offset.

Suggested wording:

> Zeek ingestion stores per-log checkpoints for restart recovery. Suricata follows newly appended EVE JSON records and uses database uniqueness controls to avoid duplicate storage.

### 5. Describe VirusTotal Precisely

VirusTotal is not part of the deterministic numerical score. The current sequence is:

1. Match enabled cached and bulk providers.
2. Calculate the Python score.
3. Request the AI assessment.
4. If the AI classification is Dangerous, use a fresh cached VirusTotal result or request public-IP verification.
5. Store VirusTotal as `corroborated`, `not_corroborated`, or `unavailable` verification evidence.

A no-detection result does not lower a classification. Private, loopback, link-local, multicast, reserved, and `100.64.0.0/10` addresses are not queried. The API key is never included in AI evidence or dashboard responses.

### 6. Frame the Score as a Heuristic

The score is an investigation-priority and evidence-strength heuristic, not a probability of compromise. Keep the six-category table, but explicitly state that the weights are design choices requiring evaluation. Avoid claiming that a higher score proves an attack.

The current policy is:

| Category | Maximum |
| --- | ---: |
| Sensor finding severity | 20 |
| Behavior and time correlation | 20 |
| Cached and bulk threat intelligence | 20 |
| MITRE ATT&CK relevance | 10 |
| Registered IP importance and traffic direction | 10 |
| Suricata-Zeek corroboration | 10 |
| **Python maximum** | **90** |

AI may adjust the Python total by `-10` to `+10`. Materially disputed sensor findings force human review. The stored outcome boundaries are Safe `0-29`, Human Review Required `30-69`, High Risk `70-84`, and Dangerous `85-100`.

### 7. Add the Three-Model Comparison Experiment

The implementation now supports a useful secondary experiment that is missing from the draft. Three active AI profiles receive the same frozen evidence package in sequential requests. The dashboard displays all answers, records latency and parsing status, and lets an analyst select the most useful response. Candidate responses do not alter the official assessment.

This can evaluate:

- factual grounding against the same evidence;
- completeness of who, what, when, where, why, how, and next steps;
- unsupported claims;
- response latency;
- structured-output reliability; and
- analyst preference.

Because model identities are currently visible in the all-response view, describe it as a **comparative evaluation** unless the interface is changed to hide identities until voting. Do not call the current workflow blind without that control.

### 8. Make Evaluation Claims Testable

The research question is appropriate, but the report should define the experiment before claiming improvement. Include:

- participant background and sample size;
- controlled alert scenarios and ground truth;
- a baseline workflow for comparison;
- task-completion time and number of manual searches;
- classification accuracy and evidence-retrieval accuracy;
- incorrect correlation rate;
- unsupported AI statement rate;
- analyst confidence or usability measure;
- model latency and resource consumption; and
- limitations caused by a small laboratory sample.

Use wording such as **the experiment evaluates whether** until results demonstrate a reduction in time or effort.

### 9. Tighten Presentation and Citation Status

- Remove `(in Review)` from the final Literature Review heading.
- Replace the blank Figure 1 and Figure 2 placeholders with diagrams, figure numbers, captions, and in-text references.
- Ensure every numbered citation has a complete bibliography entry.
- Use official documentation for product feature comparisons involving Security Onion, Malcolm, Wazuh, Elastic, Suricata, Zeek, and Community ID.
- Use present tense for implemented behavior and future tense only for planned evaluation or future work.
- Define Tier 1, SIEM, XDR, SME, Community ID, and LLM on first use if required by the report style guide.

## Suggested Implementation Chapter Map

| Report topic | Primary implementation |
| --- | --- |
| Configuration and migration | `app/config.py`, `app/bootstrap.py`, `app/database.py`, `sql/schema.sql` |
| Suricata ingestion | `app/suricata_reader.py`, `app/main.py`, `app/normalizer.py` |
| Zeek ingestion | `app/zeek_ingest.py`, `app/zeek_normalizer.py`, `app/zeek_inventory.py` |
| Sensor correlation and cases | `app/sensor_fusion.py`, `app/correlator.py`, `app/database.py` |
| Threat intelligence | `app/threat_intel.py`, `app/virustotal.py` |
| Deterministic scoring | `app/risk_score.py`, `app/decision_engine.py` |
| AI evidence and explanation | `app/ai_client.py`, `app/case_assessment.py` |
| Three-model comparison | `app/ai_comparison.py` |
| API and dashboard | `app/dashboard.py`, `static/index.html`, `static/investigation.html`, `static/compare.html` |

## Security and Operational Caveats to Retain

- Bind the dashboard to `127.0.0.1` or a trusted management address. Binding to `0.0.0.0` exposes it on every interface, and the prototype has no built-in authentication.
- Network visibility is limited by mirror-port coverage, packet loss, sensor configuration, and encrypted payloads.
- SQLite is appropriate for the single-node prototype, not high-volume distributed monitoring.
- Threat-intelligence matches may be incomplete, stale, or wrong; no match is not proof of safety.
- AI output may be fluent but unsupported. Original evidence and human review remain authoritative.
- Legacy PCAP and response-era database structures may remain for migration compatibility, but those paths are disabled in the current analysis runtime and are outside the evaluated scope.

## Review Decision

The current development is suitable for publication to the `dev` branch after verification. The report draft is conceptually aligned with the implementation, but the factual corrections above should be applied before final submission. The strongest implementation chapter will distinguish clearly among sensor facts, deterministic Python processing, external enrichment, AI explanation, and the final human decision.
