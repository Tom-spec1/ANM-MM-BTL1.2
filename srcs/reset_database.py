import sqlite3

DB_PATH = "database/pki.db"
conn = sqlite3.connect(DB_PATH)

try:
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")

    print("=== BEFORE RESET ===")
    tables = ["certificates", "certificate_requests", "crl_records"]

    for table in tables:
        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        print(f"{table}: {cursor.fetchone()[0]} records")

    cursor.execute("DELETE FROM certificates")
    cursor.execute("DELETE FROM certificate_requests")
    cursor.execute("DELETE FROM crl_records")

    cursor.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = 'sqlite_sequence'
    """)

    if cursor.fetchone():
        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name IN ('certificates', 'certificate_requests', 'crl_records')
        """)

    conn.commit()

    print("\n=== AFTER RESET ===")
    for table in tables:
        cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
        print(f"{table}: {cursor.fetchone()[0]} records")

    print("\nSUCCESS: Business database reset completed!")
except Exception as e:
    conn.rollback()
    print("ERROR:", e)
finally:
    conn.close()
