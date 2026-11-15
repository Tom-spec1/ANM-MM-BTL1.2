import sqlite3
from pathlib import Path
from cryptography import x509

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "pki.db"
CERT_DIR = BASE_DIR / "certs"

connection = sqlite3.connect(DATABASE_PATH)
try:
    rows = connection.execute("""
        SELECT serial_number, subject, status
        FROM certificates
        ORDER BY issued_at
    """).fetchall()
finally:
    connection.close()

print("========== CERTIFICATES FOR OCSP TEST ==========")

for serial, subject, status in rows:
    print("\nSerial Number:", serial)
    print("Subject:", subject)
    print("Status:", status)

    normalized_serial = serial.replace(":", "").upper().lstrip("0")

    for path in CERT_DIR.rglob("*.crt.pem"):
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
            cert_serial = format(cert.serial_number, "X").upper().lstrip("0")
            if cert_serial == normalized_serial:
                print("Certificate file:", path.relative_to(BASE_DIR))
                break
        except Exception:
            continue
