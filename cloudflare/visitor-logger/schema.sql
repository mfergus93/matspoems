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
