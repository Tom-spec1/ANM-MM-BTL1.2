from cryptography import x509
from test_helpers import BASE_DIR, load_ca, verify_cert

ca = load_ca()
cert = x509.load_pem_x509_certificate((BASE_DIR / "certs/request/request_4.crt.pem").read_bytes())
verify_cert(cert, ca)
print("CA TEST COMPLETED SUCCESSFULLY!")
print("Issued certificate signature: VALID")
print("Issuer:", cert.issuer.rfc4514_string())
