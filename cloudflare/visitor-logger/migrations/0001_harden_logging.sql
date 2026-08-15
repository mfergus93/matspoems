ALTER TABLE visits ADD COLUMN score INTEGER;
ALTER TABLE visits ADD COLUMN confidence TEXT;
ALTER TABLE visits ADD COLUMN category TEXT;
ALTER TABLE visits ADD COLUMN reasons TEXT;
ALTER TABLE visits ADD COLUMN asn INTEGER;
ALTER TABLE visits ADD COLUMN as_organization TEXT;
ALTER TABLE visits ADD COLUMN verified_bot INTEGER NOT NULL DEFAULT 0;

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

CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events (ip_address);
