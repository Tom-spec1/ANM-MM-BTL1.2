from test_helpers import connection

conn = connection()
try:
    row = conn.execute("SELECT common_name, status, rejection_reason FROM certificate_requests WHERE request_id = 6").fetchone()
finally:
    conn.close()
assert row is not None and row["common_name"] == "zeta.local" and row["status"] == "REJECTED" and row["rejection_reason"]
print("REJECTION TEST COMPLETED SUCCESSFULLY!")
print("zeta.local is REJECTED with a recorded reason")
