# app/db.py
import sqlite3
import json
from pathlib import Path

DB = Path("phish_history.db")

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        domain TEXT,
        score INTEGER,
        flags TEXT,
        raw TEXT,
        ts TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_result(res: dict):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("INSERT INTO history (url, domain, score, flags, raw, ts) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (res.get("url"), res.get("domain"), res.get("score"), json.dumps(res.get("flags")), json.dumps(res)))
    conn.commit()
    conn.close()

def read_history(limit=200):
    conn = sqlite3.connect(DB)
    import pandas as pd
    df = pd.read_sql_query("SELECT * FROM history ORDER BY id DESC LIMIT ?", conn, params=(limit,))
    conn.close()
    return df
