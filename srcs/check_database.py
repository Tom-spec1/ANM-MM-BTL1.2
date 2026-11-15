import sqlite3

connection = sqlite3.connect("database/pki.db")
cursor = connection.cursor()
cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
    AND name NOT LIKE 'sqlite_%'
""")
tables = cursor.fetchall()

print("Tables in database:")
for table in tables:
    print("-", table[0])

connection.close()
