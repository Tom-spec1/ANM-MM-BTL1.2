import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "pki.db"

connection = sqlite3.connect(DATABASE_PATH)
try:
    result = connection.execute(
        "SELECT COUNT(*) FROM certificates WHERE status = ?",
        ("REVOKED",)
    ).fetchone()
    print("Revoked certificates:", result[0])
finally:
    connection.close()
