import os
import sqlite3
from datetime import datetime

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "qr_shield.db"
)


def init_db():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                flags TEXT,
                scanned_at TEXT NOT NULL
            )
        """)


def save_scan(url, verdict, score, flags):
    flags_text = " | ".join(flags)
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            INSERT INTO scans
            (url, verdict, score, flags, scanned_at)
            VALUES (?, ?, ?, ?, ?)
        """, (url, verdict, score, flags_text, scanned_at))


def get_statistics():
    with sqlite3.connect(DATABASE) as connection:
        rows = connection.execute(
            "SELECT verdict, COUNT(*) FROM scans GROUP BY verdict"
        ).fetchall()

    counts = dict(rows)
    safe = counts.get("SAFE", 0)
    suspicious = counts.get("SUSPICIOUS", 0)
    malicious = counts.get("MALICIOUS", 0)

    return {
        "total": safe + suspicious + malicious,
        "safe": safe,
        "suspicious": suspicious,
        "malicious": malicious
    }


def get_scan_history(limit=50):
    with sqlite3.connect(DATABASE) as connection:
        return connection.execute("""
            SELECT id, url, verdict, score, flags, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()


init_db()
