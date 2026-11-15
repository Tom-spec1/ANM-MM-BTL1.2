from test_helpers import connection

conn = connection()
try:
    row = conn.execute("SELECT common_name, status FROM certificate_requests WHERE request_id = 7").fetchone()
finally:
    conn.close()
assert row is not None and row["common_name"] == "eta.local" and row["status"] == "PENDING"
print("REQUEST TEST COMPLETED SUCCESSFULLY!")
print("eta.local is PENDING")
