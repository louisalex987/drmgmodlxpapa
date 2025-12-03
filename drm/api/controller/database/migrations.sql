CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS addons(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  version TEXT,
  description TEXT
);

CREATE TABLE IF NOT EXISTS licenses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  client_id INTEGER NOT NULL,
  addon_id INTEGER NOT NULL,
  generated_at TEXT NOT NULL,
  last_regen TEXT NOT NULL,
  expiration TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(client_id) REFERENCES clients(id),
  FOREIGN KEY(addon_id) REFERENCES addons(id)
);

CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER,
  timestamp TEXT NOT NULL,
  ip_address TEXT,
  status TEXT NOT NULL,
  details TEXT,
  FOREIGN KEY(license_id) REFERENCES licenses(id)
);