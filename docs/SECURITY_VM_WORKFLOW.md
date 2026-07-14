# Security VM Workflow

This document shows the current path from network sensors to a case, deterministic scoring, AI-assisted triage, optional VirusTotal verification, analyst reassessment, and response.

> Open this file in GitHub or use **Markdown: Open Preview** in VS Code to render the Mermaid diagrams.

## End-To-End System

```mermaid
flowchart TB
    USER([Administrator / analyst])
    DEVICE[Internal devices]
    INTERNET[(External network)]

    subgraph SETUP[1. Bootstrap and Configuration]
        BOOT[python -m app.bootstrap]
        OS[Check Ubuntu version<br/>Zeek recommended on 22.04+]
        IFACES[Choose external and internal interfaces]
        ROUTERSETUP[Optional router setup<br/>netplan + forwarding<br/>explicit firewalld zones]
        INSTALL[Check/install Suricata, Zeek,<br/>tshark/dumpcap and Python packages]
        CONFIG[Write ignored local config.yaml]
        DBINIT[(Initialize or migrate SQLite<br/>without deleting existing data)]

        BOOT --> OS --> IFACES --> ROUTERSETUP
        IFACES --> INSTALL --> CONFIG --> DBINIT
    end

    subgraph NETWORK[2. Network Sensors]
        ROUTER[Security VM router/firewall]
        SURICATA[Suricata signature findings]
        EVE[/EVE JSON alerts/]
        ZEEK[Zeek behavior and protocol metadata]
        ZLOGS[/notice, conn, DNS, TLS, HTTP,<br/>files, weird, SSH and X.509 logs/]
        CAPTURE[Optional rolling packet capture]
        PCAPS[/Local forensic PCAP files/]

        DEVICE -->|routed traffic| ROUTER --> INTERNET
        ROUTER -. observed traffic .-> SURICATA --> EVE
        ROUTER -. observed traffic .-> ZEEK --> ZLOGS
        ROUTER -. observed traffic .-> CAPTURE --> PCAPS
    end

    subgraph RUNTIME[3. One-Command Runtime]
        RUNALL[app.main run-all<br/>localhost dashboard by default]
        REQUIRED[Required workers<br/>Suricata ingest + Zeek ingest<br/>+ dashboard]
        OPTIONAL[Conditional optional workers<br/>PCAP capture + bulk threat-intel refresh]

        RUNALL --> REQUIRED
        RUNALL --> OPTIONAL
    end

    subgraph CASES[4. Normalize, Correlate and Identify]
        SNORM[Normalize Suricata alert<br/>assign SUR event UID]
        ZNORM[Normalize Zeek logs<br/>assign ZEK event UID]
        ZNOTICE{Alert-like Zeek finding?}
        ZCONTEXT[Store protocol log as case context]
        CORRELATE[Correlate by Community ID first<br/>then bidirectional flow + time]
        CASE[(Case with CASE UID<br/>and separate sensor findings)]

        EVE --> SNORM --> CORRELATE
        ZLOGS --> ZNORM --> ZNOTICE
        ZNOTICE -->|yes| CORRELATE
        ZNOTICE -->|no| ZCONTEXT
        CORRELATE --> CASE
        ZCONTEXT --> CASE
    end

    subgraph PREAI[5. Python Deterministic Evidence]
        ASSETS[(Registered asset inventory)]
        FEEDS[Cached and bulk providers<br/>ThreatFox, URLhaus, SSLBL,<br/>Spamhaus, OpenPhish, IPsum,<br/>Feodo and cached OTX]
        SCORE[Deterministic score 0-90<br/>sensor severity 0-20<br/>behavior/time 0-20<br/>threat intelligence 0-20<br/>MITRE relevance 0-10<br/>asset/direction 0-10<br/>sensor corroboration 0-10]
        PACKAGE[Case evidence package<br/>Suricata + Zeek + assets + MITRE<br/>cached threat intelligence + score]

        CASE --> SCORE
        ASSETS --> SCORE
        FEEDS --> SCORE
        CASE --> PACKAGE
        SCORE --> PACKAGE
        ASSETS --> PACKAGE
        FEEDS --> PACKAGE
    end

    subgraph AI[6. Bounded AI Second Opinion]
        PROFILE[(Selected AI profile UID<br/>provider + model + endpoint)]
        PROMPT[Versioned prompt<br/>adjustment limited to -10 through +10]
        MODEL[Configured compatible AI service]
        REPORT[(Structured assessment<br/>classification, confidence,<br/>adjustment, reason, action)]

        PACKAGE --> PROMPT
        PROFILE --> PROMPT --> MODEL --> REPORT
    end

    subgraph DECISION[7. Python Final Decision]
        CLAMP[Clamp AI adjustment -10 to +10<br/>final score = clamp Python + AI, 0-100]
        DISPUTE{Material sensor dispute?}
        OUTCOME{Score outcome}
        SAFE[Safe 0-29]
        REVIEW[Human Review Required 30-69]
        HIGH[High Risk 70-84]
        DANGER[Dangerous 85-100]

        SCORE --> CLAMP
        REPORT --> CLAMP --> DISPUTE
        DISPUTE -->|yes| REVIEW
        DISPUTE -->|no| OUTCOME
        OUTCOME --> SAFE
        OUTCOME --> REVIEW
        OUTCOME --> HIGH
        OUTCOME --> DANGER
    end

    subgraph VT[8. Post-AI VirusTotal Verification]
        AIDANGER{AI classification Dangerous?}
        ELIGIBLE{Valid global IP and provider configured?}
        CACHE{Fresh cache exists?}
        QUERY[Query VirusTotal]
        VSTORE[(Store verification separately<br/>no score change)]
        SKIP[Store not requested or unavailable]

        REPORT --> AIDANGER
        AIDANGER -->|yes| ELIGIBLE
        AIDANGER -->|no| SKIP --> VSTORE
        ELIGIBLE -->|yes| CACHE
        ELIGIBLE -->|no| SKIP
        CACHE -->|yes| VSTORE
        CACHE -->|no| QUERY --> VSTORE
    end

    subgraph STORAGE[9. Audit and Response]
        STORE[(SQLite system of record<br/>cases, sensor events, score history,<br/>AI assessments, verification,<br/>reviews and response history)]
        MODE{Runtime mode}
        RECORD[alert_only: record only]
        QUEUE[detection: analyst enforcement queue]
        BLOCK[prevention: explicit-zone<br/>temporary firewalld block when gated]

        CASE --> STORE
        SCORE --> STORE
        REPORT --> STORE
        VSTORE --> STORE
        SAFE --> STORE
        REVIEW --> STORE
        HIGH --> STORE
        DANGER --> STORE
        DANGER --> MODE
        MODE --> RECORD
        MODE --> QUEUE
        MODE --> BLOCK --> STORE
    end

    subgraph ANALYST[10. Investigation and Reassessment]
        DASH[Dashboard<br/>manual Refresh]
        INVESTIGATE[Case investigation by CASE UID<br/>complete sensor timeline and evidence]
        FEEDBACK[Analyst feedback and override]
        REASSESS[Explicit Reassess Case<br/>recompute 0-90 + one AI request]
        MANUALVT[Explicit Refresh VirusTotal<br/>no automatic AI request]
        FORENSICS[Optional preserve evidence<br/>Zeek context + local PCAP reference]

        STORE --> DASH --> INVESTIGATE
        INVESTIGATE --> FEEDBACK --> STORE
        INVESTIGATE --> REASSESS --> SCORE
        INVESTIGATE --> MANUALVT --> VSTORE
        INVESTIGATE --> FORENSICS
        PCAPS --> FORENSICS
    end

    USER --> BOOT
    USER --> RUNALL
    USER --> DASH
    DBINIT --> RUNALL
```

## Reassessment Sequence

```mermaid
sequenceDiagram
    participant Analyst
    participant API as Case API
    participant DB as SQLite
    participant Python as Python scorer
    participant AI as Selected AI profile
    participant VT as VirusTotal

    Analyst->>API: Reassess CASE-YYYYMMDD-NNNNNN
    API->>DB: Load all Suricata, Zeek, TI, asset, review and prior verification evidence
    API->>Python: Recalculate deterministic categories (0-90)
    Python->>AI: Send case evidence and deterministic breakdown
    AI-->>Python: Classification, confidence and adjustment (-10 to +10)
    Python->>Python: Clamp adjustment and calculate provisional 0-100 outcome
    alt AI classification is Dangerous
        Python->>VT: Use fresh cache or query eligible global IPs
        VT-->>Python: Separate verification result
    else AI classification is not Dangerous
        Python->>DB: Store not_requested verification state
    end
    Python->>DB: Store score, AI assessment, verification and response audit
    Python-->>Analyst: Updated case workspace
    Note over Python,AI: VirusTotal never changes the numerical score
    Note over Python,AI: No automatic third AI request occurs
```

## Sensor Responsibilities

| Source | Starts a case? | Main contribution |
|---|---:|---|
| Suricata `alert` | Yes | Signature, category, priority, flow and Community ID |
| Zeek `notice.log` | Yes | Behavioral or policy finding |
| Zeek protocol logs | No, by themselves | Connection, DNS, TLS/certificate, HTTP, file, SSH and X.509 context |
| Zeek `weird.log` | Context by default | Protocol anomaly requiring corroboration |
| Rolling PCAP | No | Optional local forensic preservation; never sent in AI prompts |
| Cached/bulk threat intelligence | No | Pre-AI indicator matches and up to 20 deterministic points |
| VirusTotal | No | Post-AI verification only; zero score points |
| Registered assets | No | Analyst-defined business impact and traffic-direction context |

## Security Boundaries

- Python owns the deterministic score, final classification, and response action.
- The AI model supplies only a bounded `-10` to `+10` adjustment and explanation.
- A materially disputed sensor finding forces Human Review Required.
- VirusTotal no-detection results never lower a classification.
- Private, loopback, link-local, multicast, reserved, and `100.64.0.0/10` addresses are never queried through VirusTotal.
- API keys, Gmail app passwords, and raw PCAP data are not sent to the AI model or returned in dashboard evidence.
- PCAP collection is optional and remains local for explicit forensic preservation.
- The dashboard binds to localhost by default. Binding to `0.0.0.0` is an explicit, warned lab-only choice.
- firewalld commands always specify the configured zone.
