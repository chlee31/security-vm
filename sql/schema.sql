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
  mitre_id TEXT,
  mitre_name TEXT,
  python_initial_score INTEGER,
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
CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL,
  name TEXT,
  reason TEXT,
  added_by TEXT,
  start_time TEXT,
  expiry_time TEXT,
  status TEXT DEFAULT 'active',
  notes TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

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

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  network_interface TEXT DEFAULT 'ens37',
  asset_score INTEGER NOT NULL,
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
  risk_adjustment INTEGER,
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
  raw_response TEXT,
  elapsed_ms INTEGER,
  prompt_sha256 TEXT,
  prompt_chars INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evaluation_scenarios (
  scenario_uid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  experiment_type TEXT NOT NULL,
  ground_truth_class TEXT NOT NULL,
  authorized_activity INTEGER,
  attack_succeeded INTEGER,
  source_ip TEXT,
  destination_ip TEXT,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  expected_case_count INTEGER NOT NULL DEFAULT 1,
  expected_min_classification TEXT,
  expected_max_classification TEXT,
  expected_sensors TEXT NOT NULL DEFAULT '[]',
  candidate_scope_json TEXT NOT NULL DEFAULT '{}',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evaluation_case_links (
  scenario_uid TEXT NOT NULL,
  case_uid TEXT NOT NULL,
  relationship_status TEXT NOT NULL DEFAULT 'expected_related',
  analyst_confirmed INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scenario_uid, case_uid),
  FOREIGN KEY (scenario_uid) REFERENCES evaluation_scenarios(scenario_uid)
);

CREATE TABLE IF NOT EXISTS evaluation_event_labels (
  scenario_uid TEXT NOT NULL,
  event_uid TEXT NOT NULL,
  event_sensor TEXT NOT NULL,
  expected_case_uid TEXT,
  actual_case_uid TEXT,
  expected_membership INTEGER NOT NULL,
  actual_membership INTEGER NOT NULL,
  label TEXT NOT NULL,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scenario_uid, event_sensor, event_uid),
  FOREIGN KEY (scenario_uid) REFERENCES evaluation_scenarios(scenario_uid)
);

CREATE TABLE IF NOT EXISTS evaluation_scoring_runs (
  run_uid TEXT PRIMARY KEY,
  scenario_uid TEXT,
  case_uid TEXT NOT NULL,
  evaluation_type TEXT NOT NULL,
  baseline_policy TEXT NOT NULL,
  experimental_parameters_json TEXT NOT NULL DEFAULT '{}',
  baseline_score REAL NOT NULL,
  experimental_score REAL NOT NULL,
  baseline_classification TEXT NOT NULL,
  experimental_classification TEXT NOT NULL,
  score_difference REAL NOT NULL,
  result_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scenario_uid) REFERENCES evaluation_scenarios(scenario_uid)
);

CREATE TABLE IF NOT EXISTS evaluation_model_reviews (
  review_uid TEXT PRIMARY KEY,
  comparison_run_uid TEXT NOT NULL,
  profile_uid TEXT NOT NULL,
  anonymous_label TEXT NOT NULL,
  grounding_score INTEGER NOT NULL,
  completeness_score INTEGER NOT NULL,
  next_steps_score INTEGER NOT NULL,
  uncertainty_score INTEGER NOT NULL,
  usefulness_score INTEGER NOT NULL,
  supported_claims INTEGER NOT NULL DEFAULT 0,
  unsupported_claims INTEGER NOT NULL DEFAULT 0,
  contradicted_claims INTEGER NOT NULL DEFAULT 0,
  undecidable_claims INTEGER NOT NULL DEFAULT 0,
  notes TEXT,
  reviewer_name TEXT NOT NULL,
  reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(comparison_run_uid, profile_uid)
);

CREATE TABLE IF NOT EXISTS ai_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  assessment_type TEXT NOT NULL,
  provider TEXT,
  model_name TEXT NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL,
  risk_adjustment INTEGER,
  reason TEXT,
  recommended_action TEXT,
  evidence_sources_json TEXT,
  response_time_ms INTEGER,
  raw_response TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (detection_id) REFERENCES detections(id)
);

CREATE TABLE IF NOT EXISTS score_breakdowns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER NOT NULL,
  ai_report_id INTEGER,
  assessment_type TEXT NOT NULL DEFAULT 'initial',
  sensor_severity INTEGER NOT NULL DEFAULT 0,
  behavior_correlation INTEGER NOT NULL DEFAULT 0,
  threat_intelligence INTEGER NOT NULL DEFAULT 0,
  mitre_relevance INTEGER NOT NULL DEFAULT 0,
  asset_direction INTEGER NOT NULL DEFAULT 0,
  sensor_corroboration INTEGER NOT NULL DEFAULT 0,
  python_score INTEGER NOT NULL DEFAULT 0,
  llm_adjustment_raw INTEGER NOT NULL DEFAULT 0,
  llm_adjustment_applied INTEGER NOT NULL DEFAULT 0,
  provisional_score INTEGER NOT NULL DEFAULT 0,
  forced_review INTEGER NOT NULL DEFAULT 0,
  forced_review_reason TEXT,
  details_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (detection_id) REFERENCES detections(id),
  FOREIGN KEY (ai_report_id) REFERENCES ai_reports(id)
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
  risk_adjustment INTEGER,
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

CREATE TABLE IF NOT EXISTS responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  final_score INTEGER,
  final_classification TEXT,
  final_action TEXT,
  target_ip TEXT,
  response_method TEXT,
  response_status TEXT,
  response_time_ms INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS firewall_blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  ip_address TEXT NOT NULL,
  direction TEXT,
  zone TEXT,
  reason TEXT,
  firewall_rule TEXT,
  timeout_seconds INTEGER,
  status TEXT DEFAULT 'active',
  response_status TEXT,
  response_time_ms INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  released_at TEXT,
  released_by TEXT,
  release_reason TEXT
);

CREATE TABLE IF NOT EXISTS notification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  response_id INTEGER,
  channel TEXT NOT NULL,
  recipient TEXT,
  subject TEXT,
  status TEXT NOT NULL,
  error TEXT,
  cooldown_key TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  sent_at TEXT
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
  original_score INTEGER NOT NULL,
  original_classification TEXT,
  original_action TEXT,
  review_status TEXT DEFAULT 'pending' CHECK(review_status IN ('pending', 'confirmed', 'overridden', 'expired')),
  analyst_name TEXT,
  analyst_score INTEGER,
  analyst_classification TEXT,
  analyst_action TEXT,
  analyst_notes TEXT,
  due_at TEXT NOT NULL,
  reviewed_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

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
CREATE INDEX IF NOT EXISTS idx_score_breakdowns_detection
  ON score_breakdowns(detection_id, assessment_type);
CREATE INDEX IF NOT EXISTS idx_vt_verifications_detection
  ON virustotal_verifications(detection_id, assessment_stage);


CREATE INDEX IF NOT EXISTS idx_ai_assessments_detection
ON ai_assessments(detection_id, assessment_type);
