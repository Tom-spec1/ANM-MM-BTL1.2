import sqlite3

DB_PATH = "database/pki.db"
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("=== DATABASE TABLES ===")
cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    AND name NOT LIKE 'sqlite_%'
""")
tables = cursor.fetchall()

for (table,) in tables:
    print(f"\nTable: {table}")
    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
    count = cursor.fetchone()[0]
    print(f"Records: {count}")
    cursor.execute(f'PRAGMA table_info("{table}")')
    columns = cursor.fetchall()
    print("Columns:", [column[1] for column in columns])

conn.close()
