from test_helpers import BASE_DIR, connection

conn = connection()
try:
    rows = conn.execute("SELECT request_id, status FROM certificate_requests WHERE request_id BETWEEN 1 AND 5 ORDER BY request_id").fetchall()
    cert_count = conn.execute("SELECT COUNT(*) FROM certificates WHERE request_id BETWEEN 1 AND 5").fetchone()[0]
finally:
    conn.close()
assert len(rows) == 5 and all(r["status"] == "APPROVED" for r in rows) and cert_count == 5
assert all((BASE_DIR / f"certs/request/request_{i}.crt.pem").exists() for i in range(1, 6))
print("APPROVAL TEST COMPLETED SUCCESSFULLY!")
print("Requests 1..5 are APPROVED and have issued certificates")
