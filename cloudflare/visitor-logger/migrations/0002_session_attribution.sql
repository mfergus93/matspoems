ALTER TABLE visits ADD COLUMN visitor_id TEXT;
ALTER TABLE visits ADD COLUMN session_id TEXT;
ALTER TABLE visits ADD COLUMN source TEXT;
ALTER TABLE visits ADD COLUMN utm_source TEXT;
ALTER TABLE visits ADD COLUMN utm_medium TEXT;
ALTER TABLE visits ADD COLUMN utm_campaign TEXT;
ALTER TABLE visits ADD COLUMN classifier_version TEXT;
ALTER TABLE visits ADD COLUMN bot_score INTEGER;
ALTER TABLE visits ADD COLUMN ja3_hash TEXT;
ALTER TABLE visits ADD COLUMN ja4 TEXT;
ALTER TABLE visits ADD COLUMN js_detection_passed INTEGER;

CREATE TABLE IF NOT EXISTS visitor_profiles (
  visitor_id TEXT PRIMARY KEY, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  first_source TEXT, last_source TEXT, first_referrer TEXT, last_referrer TEXT,
  last_referred_at TEXT, known_referred_visitor INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, visitor_id TEXT NOT NULL, started_at TEXT NOT NULL,
  last_event_at TEXT NOT NULL, entry_path TEXT, source TEXT, referrer TEXT,
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
CREATE INDEX IF NOT EXISTS idx_visits_session_id ON visits (session_id);
CREATE INDEX IF NOT EXISTS idx_analytics_session_id ON analytics_events (session_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_classification_session_id ON classification_events (session_id, occurred_at);


