import sqlite3
from pathlib import Path
from cryptography import x509

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "pki.db"
CRL_PATH = BASE_DIR / "certs" / "crl" / "rootCA.crl.pem"

with open(CRL_PATH, "rb") as file:
    crl = x509.load_pem_x509_crl(file.read())

crl_serials = {
    format(cert.serial_number, "X").upper().lstrip("0")
    for cert in crl
}

connection = sqlite3.connect(DATABASE_PATH)
try:
    rows = connection.execute("""
        SELECT serial_number, status, revoked_at, revocation_reason
        FROM certificates
        WHERE status = 'REVOKED'
    """).fetchall()
finally:
    connection.close()

db_serials = {
    row[0].replace(":", "").upper().lstrip("0")
    for row in rows
}

print("========== CRL DATABASE VERIFICATION ==========")
print("\n1. Certificates in CRL:")
for serial in sorted(crl_serials):
    print(serial)

print("\n2. Revoked certificates in Database:")
for row in rows:
    print("Serial Number:", row[0])
    print("Status:", row[1])
    print("Revoked At:", row[2])
    print("Reason:", row[3])
    print()

print("3. Comparison:")
print("CRL entries:", len(crl_serials))
print("Database revoked entries:", len(db_serials))

if crl_serials == db_serials:
    print("\nSUCCESS: CRL and Database match!")
else:
    print("\nWARNING: CRL and Database do not match!")
    print("Missing in CRL:", db_serials - crl_serials)
    print("Extra in CRL:", crl_serials - db_serials)
