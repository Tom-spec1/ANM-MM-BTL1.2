from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_helpers import load_ca
from ocsp import create_ocsp_response

ca = load_ca()
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.now(timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unknown.test")]))
    .issuer_name(ca.subject)
    .public_key(key.public_key())
    .serial_number(0x123456789ABCDEF)
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(days=1))
    .sign(key, hashes.SHA256())
)
req = ocsp.OCSPRequestBuilder().add_certificate(cert, ca, hashes.SHA1()).build()
resp = create_ocsp_response(req)
assert resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
assert resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN
assert req.serial_number == resp.serial_number
print("OCSP UNKNOWN TEST SUCCESS: 0x123456789ABCDEF -> UNKNOWN")
