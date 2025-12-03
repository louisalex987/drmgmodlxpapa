import sqlite3
import os
from shared.config.env import env

def init_db():
    db_path = env()["DB_PATH"]
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create tables
    c.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS addons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT,
            description TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            client_id INTEGER,
            addon_id INTEGER,
            generated_at TEXT,
            last_regen TEXT,
            expiration TEXT,
            active INTEGER DEFAULT 1,
            FOREIGN KEY(client_id) REFERENCES clients(id),
            FOREIGN KEY(addon_id) REFERENCES addons(id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER,
            timestamp TEXT,
            ip_address TEXT,
            status TEXT,
            details TEXT,
            FOREIGN KEY(license_id) REFERENCES licenses(id)
        )
    ''')
    
    # Insert default data if empty
    c.execute("SELECT count(*) FROM clients")
    if c.fetchone()[0] == 0:
        print("Seeding default data...")
        c.execute("INSERT INTO clients (name, email) VALUES (?, ?)", ("Test Client", "client@example.com"))
        c.execute("INSERT INTO addons (name, version, description) VALUES (?, ?, ?)", ("My GMod Addon", "1.0.0", "A cool addon"))
        conn.commit()
        
    conn.close()
    print(f"Database initialized at {db_path}")

if __name__ == "__main__":
    init_db()
