from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ca import submit_certificate_request


BASE_DIR = Path(__file__).resolve().parent.parent
REQUEST_DIR = BASE_DIR / "requests"
PRIVATE_DIR = BASE_DIR / "private" / "new_requests"

REQUEST_DIR.mkdir(parents=True, exist_ok=True)
PRIVATE_DIR.mkdir(parents=True, exist_ok=True)


REQUESTS = [
    ("alpha.local", "Alpha Department"),
    ("beta.local", "Beta Department"),
    ("gamma.local", "Gamma Department"),
    ("delta.local", "Delta Department"),
    ("epsilon.local", "Epsilon Department"),
    ("zeta.local", "Zeta Department"),
    ("eta.local", "Eta Department"),
]


for common_name, department in REQUESTS:
    print("\n" + "=" * 55)
    print(f"Creating CSR for: {common_name}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Ho Chi Minh City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Project"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    key_path = PRIVATE_DIR / f"{common_name}.key.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    csr_path = REQUEST_DIR / f"{common_name}.csr.pem"
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    request_id = submit_certificate_request(csr_path)

    print(f"Saved private key: {key_path}")
    print(f"Saved CSR: {csr_path}")
    print(f"Created Request ID: {request_id}")


print("\n" + "=" * 55)
print("ALL 7 CERTIFICATE REQUESTS CREATED SUCCESSFULLY!")
