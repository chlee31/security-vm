CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
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
  pcap_point TEXT,
  raw_json TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_alert_id INTEGER,
  first_seen TEXT,
  last_seen TEXT,
  src_ip TEXT,
  dest_ip TEXT,
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

CREATE TABLE IF NOT EXISTS incident_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  detection_id INTEGER,
  alert_id INTEGER,
  incident_start_time TEXT,
  incident_end_time TEXT,
  incident_pcap_path TEXT,
  pcap_summary_path TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ollama_reports (
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
  raw_response TEXT,
  elapsed_ms INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
