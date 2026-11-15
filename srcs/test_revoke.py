from test_helpers import connection

conn = connection()
try:
    rows = conn.execute("SELECT request_id, serial_number, status, revoked_at, revocation_reason FROM certificates ORDER BY request_id").fetchall()
finally:
    conn.close()
assert [r["status"] for r in rows[:3]] == ["REVOKED", "REVOKED", "REVOKED"]
assert all(r["revoked_at"] and r["revocation_reason"] for r in rows[:3])
assert [r["status"] for r in rows[3:]] == ["VALID", "VALID"]
print("REVOCATION TEST COMPLETED SUCCESSFULLY!")
print("Requests 1..3 are REVOKED; requests 4..5 remain VALID")
