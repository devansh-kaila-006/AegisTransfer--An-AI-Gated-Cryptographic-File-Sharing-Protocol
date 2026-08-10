import sqlite3
import datetime

DB_NAME = "audit_log.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            encryption_status TEXT,
            signature_status TEXT,
            ids_prediction TEXT,
            ids_confidence REAL,
            response_action TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_event(filename, enc_status, sig_status, ids_prediction, ids_confidence, action):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO audit (timestamp, filename, encryption_status, signature_status, ids_prediction, ids_confidence, response_action)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (datetime.datetime.now().isoformat(), filename, enc_status, sig_status, ids_prediction, ids_confidence, action))
    conn.commit()
    conn.close()

def get_logs():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 50')
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]
