CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visited_at TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  country TEXT,
  path TEXT NOT NULL,
  referrer TEXT,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_visits_visited_at ON visits(visited_at);
CREATE INDEX IF NOT EXISTS idx_visits_ip_address ON visits(ip_address);
