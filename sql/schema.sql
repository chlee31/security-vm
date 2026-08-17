-- SENSOR INPUT AND RESUME STATE
-- Keep searchable Suricata fields beside the original JSON. The checkpoint is
-- advanced only after a record is committed so a restart favors replay over
-- silently losing evidence.
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_uid TEXT UNIQUE,
  event_fingerprint TEXT,
  suricata_event_id TEXT,
  timestamp TEXT,
  src_ip TEXT,
  dest_ip TEXT,
  src_port INTEGER,
  dest_port INTEGER,
  protocol TEXT,
  signature TEXT,
  category TEXT,
  severity INTEGER,
  priority INTEGER,
  flow_id TEXT,
  community_id TEXT,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS suricata_ingest_checkpoints (
  source TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  inode INTEGER NOT NULL,
  offset INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- CASES AND SENSOR FUSION
-- A detection is the case-level grouping presented to the analyst. Individual
-- Suricata and Zeek records remain linked through sensor_findings so the case
-- can be reconstructed and audited without flattening away source evidence.
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_uid TEXT UNIQUE,
  first_alert_id INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  src_ip TEXT,
  dest_ip TEXT,
  src_port INTEGER,
  dest_port INTEGER,
  protocol TEXT,
  community_id TEXT,
  sensor_state TEXT DEFAULT 'suricata_only',
  agreement_state TEXT DEFAULT 'single_sensor',
  correlation_method TEXT DEFAULT 'single_sensor',
  correlation_confidence REAL DEFAULT 0.5,
  detection_type TEXT,
  alert_count INTEGER,
  unique_dest_ports INTEGER,
  unique_dest_hosts INTEGER,
  time_window_seconds INTEGER,
  status TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sensor_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  sensor TEXT NOT NULL,
  sensor_event_id INTEGER NOT NULL,
  finding_type TEXT NOT NULL,
  finding_name TEXT NOT NULL,
  severity INTEGER,
  confidence REAL,
  community_id TEXT,
  raw_event TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(sensor, sensor_event_id),
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE INDEX IF NOT EXISTS idx_sensor_findings_detection
  ON sensor_findings(detection_id);
CREATE INDEX IF NOT EXISTS idx_sensor_findings_event
  ON sensor_findings(sensor, sensor_event_id);

-- THREAT-INTELLIGENCE CACHE AND PROVENANCE
-- Indicators are reusable local feed data; usage rows prove which exact match
-- was consulted for a case. Source rows record refresh health without storing
-- provider credentials.
CREATE TABLE IF NOT EXISTS threat_intel_lookups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER,
  detection_id INTEGER,
  indicator TEXT,
  indicator_type TEXT,
  source TEXT,
  lookup_result TEXT,
  malicious_count INTEGER,
  suspicious_count INTEGER,
  reputation TEXT,
  lookup_time TEXT,
  cached INTEGER DEFAULT 0,
  raw_response TEXT
);

CREATE TABLE IF NOT EXISTS threat_intel_indicators (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  source TEXT NOT NULL,
  category TEXT,
  malware_family TEXT,
  confidence INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  expires_at TEXT,
  source_reference TEXT,
  raw_data TEXT,
  imported_at TEXT NOT NULL,
  UNIQUE(indicator, indicator_type, source)
);

CREATE TABLE IF NOT EXISTS threat_intel_sources (
  source TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'not_active',
  indicator_count INTEGER DEFAULT 0,
  last_attempt TEXT,
  last_success TEXT,
  last_error TEXT,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_intel_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  alert_id INTEGER,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  source TEXT NOT NULL,
  stage TEXT NOT NULL,
  matched INTEGER DEFAULT 1,
  details_json TEXT,
  used_at TEXT NOT NULL,
  UNIQUE(detection_id, indicator, indicator_type, source, stage)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator
  ON threat_intel_indicators(indicator, indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_source
  ON threat_intel_indicators(source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_usage_source
  ON threat_intel_usage(source, used_at);

-- REGISTERED IP ROLE CONTEXT
-- Retained for schema compatibility and optional analyst context. These rows
-- describe expected machine roles; they are not endpoint telemetry.
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  network_interface TEXT DEFAULT 'ens37',
  function TEXT,
  notes TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS zeek_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_uid TEXT UNIQUE,
  zeek_uid TEXT,
  log_type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  source_ip TEXT,
  source_port INTEGER,
  destination_ip TEXT,
  destination_port INTEGER,
  protocol TEXT,
  community_id TEXT,
  event_name TEXT,
  message TEXT,
  sub_message TEXT,
  actions_json TEXT,
  raw_json TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  UNIQUE(log_type, timestamp, zeek_uid, event_name, message)
);

CREATE TABLE IF NOT EXISTS zeek_ingest_checkpoints (
  log_type TEXT PRIMARY KEY,
  path TEXT,
  inode INTEGER,
  offset INTEGER DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- AI OUTPUT AND REQUEST AUDIT
-- ai_reports stores parsed model conclusions for normal dashboard use. The
-- audit table preserves the exact prompt, normalized evidence, omissions,
-- options, hashes, and raw response needed to prove what was exchanged.
CREATE TABLE IF NOT EXISTS ai_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  ai_profile_uid TEXT,
  model_provider TEXT,
  model_name TEXT,
  model_identity TEXT,
  model_endpoint TEXT,
  model_run_id TEXT,
  prompt_version TEXT,
  classification TEXT,
  confidence TEXT,
  reason TEXT,
  recommended_action TEXT,
  summary TEXT,
  who_summary TEXT,
  what_summary TEXT,
  when_summary TEXT,
  where_summary TEXT,
  why_summary TEXT,
  how_summary TEXT,
  next_steps_json TEXT,
  threat_intel_analysis_json TEXT,
  evidence_review_json TEXT,
  raw_response TEXT,
  elapsed_ms INTEGER,
  prompt_sha256 TEXT,
  prompt_chars INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_run_audits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  ai_report_id INTEGER,
  assessment_type TEXT NOT NULL DEFAULT 'initial',
  model_run_id TEXT NOT NULL,
  ai_profile_uid TEXT,
  model_provider TEXT,
  model_name TEXT,
  model_endpoint TEXT,
  prompt_version TEXT,
  prompt_text TEXT NOT NULL,
  prompt_sha256 TEXT NOT NULL,
  prompt_chars INTEGER NOT NULL,
  prompt_bytes INTEGER NOT NULL,
  evidence_package_json TEXT NOT NULL,
  evidence_sha256 TEXT NOT NULL,
  evidence_chars INTEGER NOT NULL,
  evidence_bytes INTEGER NOT NULL,
  evidence_manifest_json TEXT NOT NULL,
  omission_manifest_json TEXT NOT NULL,
  source_map_json TEXT NOT NULL,
  request_options_json TEXT NOT NULL,
  response_metrics_json TEXT NOT NULL DEFAULT '{}',
  response_text TEXT,
  response_sha256 TEXT,
  response_chars INTEGER,
  response_bytes INTEGER,
  parse_status TEXT,
  parse_error TEXT,
  status TEXT NOT NULL DEFAULT 'prepared',
  prepared_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  responded_at TEXT,
  UNIQUE(detection_id, model_run_id),
  FOREIGN KEY (detection_id) REFERENCES detections(id),
  FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_run_audits_detection
  ON ai_run_audits(detection_id, id DESC);

-- REASSESSMENT AND POST-AI VERIFICATION
-- Assessments retain historical model passes. VirusTotal is separate evidence
-- and therefore cannot silently add or subtract from a model classification.
CREATE TABLE IF NOT EXISTS ai_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  assessment_type TEXT NOT NULL,
  provider TEXT,
  model_name TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL,
  reason TEXT,
  recommended_action TEXT,
  evidence_sources_json TEXT,
  response_time_ms INTEGER,
  raw_response TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE TABLE IF NOT EXISTS virustotal_verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  ai_report_id INTEGER,
  assessment_stage TEXT NOT NULL DEFAULT 'initial',
  ip_address TEXT,
  request_state TEXT NOT NULL,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  interpretation TEXT NOT NULL DEFAULT 'unavailable',
  malicious_count INTEGER NOT NULL DEFAULT 0,
  suspicious_count INTEGER NOT NULL DEFAULT 0,
  cached INTEGER NOT NULL DEFAULT 0,
  details_json TEXT,
  error TEXT,
  checked_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (detection_id) REFERENCES detections(id),
  FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
);

-- MODEL PROFILES AND BLIND COMPARISON RESEARCH
-- Profiles identify callable model endpoints. Each comparison freezes one
-- evidence snapshot, anonymizes candidate slots, and records votes separately
-- so model identity can be revealed only after review.
CREATE TABLE IF NOT EXISTS ai_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  provider TEXT NOT NULL,
  host TEXT NOT NULL,
  model TEXT NOT NULL,
  timeout_seconds INTEGER DEFAULT 90,
  status TEXT DEFAULT 'active',
  notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  last_selected_at TEXT
);

CREATE TABLE IF NOT EXISTS ai_comparison_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  comparison_uid TEXT NOT NULL UNIQUE,
  case_uid TEXT NOT NULL,
  detection_id INTEGER NOT NULL,
  evidence_sha256 TEXT,
  prompt_version TEXT,
  threat_intel_evidence_json TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  candidate_count INTEGER NOT NULL DEFAULT 0,
  error_message TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_comparison_runs_case
  ON ai_comparison_runs(case_uid, id DESC);

CREATE TABLE IF NOT EXISTS ai_comparison_candidates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  comparison_run_id INTEGER NOT NULL,
  anonymous_slot TEXT NOT NULL,
  ai_profile_uid TEXT NOT NULL,
  model_provider TEXT,
  model_name TEXT,
  model_identity TEXT,
  model_run_id TEXT,
  prompt_version TEXT,
  prompt_sha256 TEXT,
  classification TEXT,
  confidence TEXT,
  summary TEXT,
  who_summary TEXT,
  what_summary TEXT,
  when_summary TEXT,
  where_summary TEXT,
  why_summary TEXT,
  how_summary TEXT,
  next_steps_json TEXT,
  threat_intel_analysis_json TEXT,
  recommended_action TEXT,
  raw_response TEXT,
  elapsed_ms INTEGER,
  status TEXT NOT NULL DEFAULT 'complete',
  error_message TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id),
  UNIQUE(comparison_run_id, anonymous_slot),
  UNIQUE(comparison_run_id, ai_profile_uid)
);

CREATE TABLE IF NOT EXISTS ai_comparison_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  comparison_run_id INTEGER NOT NULL,
  analyst_name TEXT NOT NULL,
  selection TEXT NOT NULL,
  notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_comparison_votes_run
  ON ai_comparison_votes(comparison_run_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_comparison_votes_one_per_run
  ON ai_comparison_votes(comparison_run_id);

CREATE TABLE IF NOT EXISTS ai_comparison_review_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  comparison_run_id INTEGER NOT NULL,
  analyst_name TEXT NOT NULL,
  selection TEXT NOT NULL,
  notes TEXT,
  reviewed_at TEXT,
  reopened_at TEXT NOT NULL,
  FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_comparison_review_history_run
  ON ai_comparison_review_history(comparison_run_id, id DESC);

CREATE TABLE IF NOT EXISTS ai_case_explanation_promotions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  case_uid TEXT NOT NULL,
  comparison_run_id INTEGER NOT NULL,
  candidate_id INTEGER NOT NULL,
  analyst_name TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (detection_id) REFERENCES detections(id),
  FOREIGN KEY (comparison_run_id) REFERENCES ai_comparison_runs(id),
  FOREIGN KEY (candidate_id) REFERENCES ai_comparison_candidates(id)
);

CREATE INDEX IF NOT EXISTS idx_ai_case_explanation_promotions_detection
  ON ai_case_explanation_promotions(detection_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_ai_case_explanation_promotions_run
  ON ai_case_explanation_promotions(comparison_run_id, id DESC);

-- RUNTIME OBSERVABILITY AND WORKER CONTROL
-- These rows make request progress, cancellation, and process health visible
-- across browser or service restarts; they are not the case evidence itself.
CREATE TABLE IF NOT EXISTS ai_request_activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  activity_uid TEXT NOT NULL UNIQUE,
  case_uid TEXT,
  detection_id INTEGER,
  comparison_uid TEXT,
  anonymous_slot TEXT,
  assessment_type TEXT NOT NULL,
  phase TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  message TEXT NOT NULL,
  prompt_chars INTEGER,
  prompt_bytes INTEGER,
  estimated_tokens INTEGER,
  timeout_seconds INTEGER,
  elapsed_ms INTEGER,
  parse_status TEXT,
  error_message TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_request_activity_recent
  ON ai_request_activity(id DESC);
CREATE INDEX IF NOT EXISTS idx_ai_request_activity_status
  ON ai_request_activity(status, id DESC);

CREATE TABLE IF NOT EXISTS ai_worker_control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  paused INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_cancelled_detections (
  detection_id INTEGER PRIMARY KEY,
  activity_uid TEXT,
  cancelled_at TEXT NOT NULL,
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE TABLE IF NOT EXISTS runtime_components (
  component TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  pid INTEGER,
  required INTEGER NOT NULL DEFAULT 0,
  exit_code INTEGER,
  started_at TEXT,
  heartbeat_at TEXT NOT NULL
);

-- FINAL RESPONSE AND HUMAN REVIEW RECORDS
-- Keep automated outcomes, tuning labels, application events, and analyst
-- decisions separate so later review can distinguish machine output from a
-- human override.
CREATE TABLE IF NOT EXISTS responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  final_classification TEXT,
  final_action TEXT,
  target_ip TEXT,
  response_method TEXT,
  response_status TEXT,
  response_time_ms INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tuning_labels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  label TEXT CHECK(label IN ('true_positive', 'false_positive', 'authorized_test', 'unknown')),
  false_positive_reason TEXT,
  analyst_notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level TEXT NOT NULL,
  component TEXT NOT NULL,
  message TEXT NOT NULL,
  details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analyst_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL UNIQUE,
  original_classification TEXT,
  original_action TEXT,
  review_status TEXT DEFAULT 'pending' CHECK(review_status IN ('pending', 'confirmed', 'overridden', 'expired')),
  analyst_name TEXT,
  analyst_classification TEXT,
  analyst_action TEXT,
  analyst_notes TEXT,
  due_at TEXT NOT NULL,
  reviewed_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- QUERY INDEXES
-- These cover the time, UID, relationship, and lookup paths used most often by
-- ingestion workers and dashboard endpoints.
CREATE INDEX IF NOT EXISTS idx_zeek_events_time
ON zeek_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_zeek_events_uid
ON zeek_events(zeek_uid);

CREATE INDEX IF NOT EXISTS idx_zeek_events_src_dst
  ON zeek_events(source_ip, destination_ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_uid
  ON alerts(event_uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_fingerprint
  ON alerts(event_fingerprint)
  WHERE event_fingerprint IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_detections_case_uid
  ON detections(case_uid);
CREATE UNIQUE INDEX IF NOT EXISTS idx_zeek_events_event_uid
  ON zeek_events(event_uid);
CREATE INDEX IF NOT EXISTS idx_vt_verifications_detection
  ON virustotal_verifications(detection_id, assessment_stage);


CREATE INDEX IF NOT EXISTS idx_ai_assessments_detection
ON ai_assessments(detection_id, assessment_type);
