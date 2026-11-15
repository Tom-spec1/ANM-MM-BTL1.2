from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from test_helpers import BASE_DIR, load_ca, connection

ca = load_ca()
crl = x509.load_pem_x509_crl((BASE_DIR / "certs/crl/rootCA.crl.pem").read_bytes())
assert crl.issuer == ca.subject and len(crl) == 3
ca.public_key().verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)
conn = connection()
try:
    db_serials = {r[0].lstrip("0") or "0" for r in conn.execute("SELECT serial_number FROM certificates WHERE status='REVOKED'")}
finally:
    conn.close()
crl_serials = {format(r.serial_number, "X").lstrip("0") or "0" for r in crl}
assert db_serials == crl_serials
print("CRL TEST COMPLETED SUCCESSFULLY!")
print("Latest CRL signature: VALID; DB/CRL revoked serials match")
