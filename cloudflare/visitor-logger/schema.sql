CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visited_at TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  country TEXT,
  city TEXT,
  region TEXT,
  postal_code TEXT,
  path TEXT NOT NULL,
  referrer TEXT,
  user_agent TEXT,
  score INTEGER,
  confidence TEXT,
  category TEXT,
  reasons TEXT,
  asn INTEGER,
  as_organization TEXT,
  verified_bot INTEGER NOT NULL DEFAULT 0
  ,visitor_id TEXT
  ,session_id TEXT
  ,source TEXT
  ,source_evidence TEXT
  ,utm_source TEXT
  ,utm_medium TEXT
  ,utm_campaign TEXT
  ,classifier_version TEXT
  ,bot_score INTEGER
  ,ja3_hash TEXT
  ,ja4 TEXT
  ,js_detection_passed INTEGER
);

CREATE TABLE IF NOT EXISTS visitor_profiles (
  visitor_id TEXT PRIMARY KEY, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  first_source TEXT, last_source TEXT, first_referrer TEXT, last_referrer TEXT,
  last_referred_at TEXT, known_referred_visitor INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, visitor_id TEXT NOT NULL, started_at TEXT NOT NULL,
  last_event_at TEXT NOT NULL, entry_path TEXT, source TEXT, source_evidence TEXT, referrer TEXT,
  utm_source TEXT, utm_medium TEXT, utm_campaign TEXT, status TEXT NOT NULL,
  score INTEGER NOT NULL, reasons TEXT, classifier_version TEXT NOT NULL, alerted_at TEXT
);

CREATE TABLE IF NOT EXISTS analytics_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, visitor_id TEXT NOT NULL,
  session_id TEXT NOT NULL, event_type TEXT NOT NULL, path TEXT, visible_seconds INTEGER,
  referrer TEXT, classifier_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS classification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL, visitor_id TEXT NOT NULL,
  session_id TEXT NOT NULL, event_type TEXT NOT NULL, classifier_version TEXT NOT NULL,
  score INTEGER, confidence TEXT, reasons TEXT
);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  occurred_at TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  country TEXT,
  city TEXT,
  region TEXT,
  postal_code TEXT,
  path TEXT NOT NULL,
  user_agent TEXT,
  category TEXT NOT NULL,
  reason TEXT,
  asn INTEGER,
  as_organization TEXT
);

CREATE INDEX IF NOT EXISTS idx_visits_visited_at ON visits (visited_at DESC);
CREATE INDEX IF NOT EXISTS idx_visits_ip_address ON visits (ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events (ip_address);
CREATE INDEX IF NOT EXISTS idx_visits_session_id ON visits (session_id);
CREATE INDEX IF NOT EXISTS idx_analytics_session_id ON analytics_events (session_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_classification_session_id ON classification_events (session_id, occurred_at);
