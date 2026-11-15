from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from test_helpers import BASE_DIR, load_ca, verify_cert
from ocsp import create_ocsp_response

ca = load_ca()
cert = x509.load_pem_x509_certificate((BASE_DIR / "certs/request/request_4.crt.pem").read_bytes())
responder = x509.load_pem_x509_certificate((BASE_DIR / "certs/ocsp/ocsp.crt.pem").read_bytes())
verify_cert(responder, ca)
eku = responder.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
assert ExtendedKeyUsageOID.OCSP_SIGNING in eku
req = ocsp.OCSPRequestBuilder().add_certificate(cert, ca, hashes.SHA1()).build()
resp = create_ocsp_response(req)
responder.public_key().verify(
    resp.signature,
    resp.tbs_response_bytes,
    padding.PKCS1v15(),
    resp.signature_hash_algorithm,
)
print("OCSP SIGNATURE TEST SUCCESS")
print("Responder certificate chain: VALID; EKU OCSPSigning: TRUE; response signature: VALID")
