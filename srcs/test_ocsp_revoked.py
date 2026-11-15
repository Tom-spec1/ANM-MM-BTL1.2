from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
from test_helpers import BASE_DIR, load_ca
from ocsp import create_ocsp_response

ca = load_ca()
cert = x509.load_pem_x509_certificate((BASE_DIR / "certs/request/request_1.crt.pem").read_bytes())
req = ocsp.OCSPRequestBuilder().add_certificate(cert, ca, hashes.SHA1()).build()
resp = create_ocsp_response(req)
assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
assert resp.certificate_status == ocsp.OCSPCertStatus.REVOKED
print("OCSP REVOKED TEST SUCCESS: alpha.local -> REVOKED")
