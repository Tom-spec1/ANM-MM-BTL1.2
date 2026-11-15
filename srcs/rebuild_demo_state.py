"""Rebuild the complete demo PKI state for BTL 1.2.

This script makes the submission reproducible and guarantees that the Root CA
X.509 Subject embeds all four student IDs exactly as required by the assignment.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from project_config import (
    DEMO_ROOT_CA_PASSPHRASE,
    ROOT_CA_COMMON_NAME,
    ROOT_CA_COUNTRY,
    ROOT_CA_LOCALITY,
    ROOT_CA_ORGANIZATION,
    ROOT_CA_ORGANIZATIONAL_UNIT,
    ROOT_CA_STATE,
    STUDENT_IDS,
)

BASE_DIR = Path(__file__).resolve().parent.parent
CERTS = BASE_DIR / "certs"
PRIVATE = BASE_DIR / "private"
REQUESTS = BASE_DIR / "requests"
DATABASE = BASE_DIR / "database"
DB_PATH = DATABASE / "pki.db"
SCHEMA_PATH = DATABASE / "schema.sql"

PASSPHRASE = os.getenv("PKI_ROOT_CA_PASSPHRASE", DEMO_ROOT_CA_PASSPHRASE)
os.environ["PKI_ROOT_CA_PASSPHRASE"] = PASSPHRASE


def write_private_key(path: Path, key, password: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encryption = (
        serialization.BestAvailableEncryption(password.encode("utf-8"))
        if password
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
    )


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def subject(*, ou: str, cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, ROOT_CA_COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ROOT_CA_STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, ROOT_CA_LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ROOT_CA_ORGANIZATION),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def sign_end_entity(
    *,
    ca_key,
    ca_cert,
    key,
    cert_subject,
    serial: int,
    eku,
    san=None,
    days=365,
):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert_subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def rebuild_filesystem() -> None:
    for path in (CERTS, PRIVATE, REQUESTS):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)

    (REQUESTS / "ocsp").mkdir(parents=True, exist_ok=True)
    (REQUESTS / "test").mkdir(parents=True, exist_ok=True)
    (PRIVATE / "server").mkdir(parents=True, exist_ok=True)
    (PRIVATE / "ocsp").mkdir(parents=True, exist_ok=True)
    (PRIVATE / "new_requests").mkdir(parents=True, exist_ok=True)
    (CERTS / "request").mkdir(parents=True, exist_ok=True)
    (CERTS / "ocsp").mkdir(parents=True, exist_ok=True)
    (CERTS / "crl").mkdir(parents=True, exist_ok=True)

    (REQUESTS / "request_ext.cnf").write_text(
        """[server_cert]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = request.local
""",
        encoding="utf-8",
    )
    (REQUESTS / "server_ext.cnf").write_text(
        """[server_cert]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
""",
        encoding="utf-8",
    )
    (REQUESTS / "ocsp" / "ocsp_ext.cnf").write_text(
        """[ocsp_cert]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
""",
        encoding="utf-8",
    )


def rebuild_database() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.commit()
    finally:
        connection.close()


def create_ca_and_service_certificates():
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_subject = subject(ou=ROOT_CA_ORGANIZATIONAL_UNIT, cn=ROOT_CA_COMMON_NAME)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    write_private_key(PRIVATE / "rootCA.key.pem", ca_key, PASSPHRASE)
    write_cert(CERTS / "rootCA.crt.pem", ca_cert)
    (CERTS / "rootCA.crt.srl").write_text("1000\n", encoding="ascii")

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = subject(ou="Web Server Department", cn="localhost")
    server_csr = x509.CertificateSigningRequestBuilder().subject_name(server_subject).sign(server_key, hashes.SHA256())
    (REQUESTS / "server.csr.pem").write_bytes(server_csr.public_bytes(serialization.Encoding.PEM))
    server_cert = sign_end_entity(
        ca_key=ca_key,
        ca_cert=ca_cert,
        key=server_key,
        cert_subject=server_subject,
        serial=0x5001,
        eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        san=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )
    write_private_key(PRIVATE / "server" / "server.key.pem", server_key)
    write_cert(CERTS / "server.crt.pem", server_cert)

    ocsp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ocsp_subject = subject(ou="OCSP Department", cn="PKI OCSP Responder")
    ocsp_csr = x509.CertificateSigningRequestBuilder().subject_name(ocsp_subject).sign(ocsp_key, hashes.SHA256())
    (REQUESTS / "ocsp" / "ocsp.csr.pem").write_bytes(ocsp_csr.public_bytes(serialization.Encoding.PEM))
    ocsp_cert = sign_end_entity(
        ca_key=ca_key,
        ca_cert=ca_cert,
        key=ocsp_key,
        cert_subject=ocsp_subject,
        serial=0x5002,
        eku=[ExtendedKeyUsageOID.OCSP_SIGNING],
    )
    write_private_key(PRIVATE / "ocsp" / "ocsp.key.pem", ocsp_key)
    write_cert(CERTS / "ocsp" / "ocsp.crt.pem", ocsp_cert)
    (PRIVATE / "ocsp" / "public_from_cert.pem").write_bytes(
        ocsp_cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    (PRIVATE / "ocsp" / "public_from_key.pem").write_bytes(
        ocsp_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return ca_key, ca_cert


def create_requests_and_demo_state():
    from ca import approve_request, generate_crl, reject_request, revoke_certificate, submit_certificate_request

    data = [
        ("alpha.local", "Alpha Department"),
        ("beta.local", "Beta Department"),
        ("gamma.local", "Gamma Department"),
        ("delta.local", "Delta Department"),
        ("epsilon.local", "Epsilon Department"),
        ("zeta.local", "Zeta Department"),
        ("eta.local", "Eta Department"),
    ]
    request_ids = []
    for cn, ou in data:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        req_subject = subject(ou=ou, cn=cn)
        csr = x509.CertificateSigningRequestBuilder().subject_name(req_subject).sign(key, hashes.SHA256())
        write_private_key(PRIVATE / "new_requests" / f"{cn}.key.pem", key)
        csr_path = REQUESTS / f"{cn}.csr.pem"
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        request_ids.append(submit_certificate_request(csr_path))

    for request_id in request_ids[:5]:
        approve_request(
            request_id,
            REQUESTS / "request_ext.cnf",
            CERTS / "request" / f"request_{request_id}.crt.pem",
        )

    reject_request(request_ids[5], "Certificate request rejected due to policy requirements.")

    connection = sqlite3.connect(DB_PATH)
    serials = [
        row[0]
        for row in connection.execute(
            "SELECT serial_number FROM certificates ORDER BY request_id ASC"
        ).fetchall()
    ]
    connection.close()

    reasons = [
        "Key compromise - alpha.local demo revocation.",
        "Key compromise - beta.local demo revocation.",
        "Key compromise - gamma.local demo revocation.",
    ]
    for serial, reason in zip(serials[:3], reasons):
        revoke_certificate(serial, reason)
        generate_crl()


def create_ocsp_artifacts():
    from ocsp import create_ocsp_response

    ca_cert = x509.load_pem_x509_certificate((CERTS / "rootCA.crt.pem").read_bytes())
    target = x509.load_pem_x509_certificate((CERTS / "request" / "request_4.crt.pem").read_bytes())
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(target, ca_cert, hashes.SHA1())
        .build()
    )
    request_der = request.public_bytes(serialization.Encoding.DER)
    response = create_ocsp_response(request)
    response_der = response.public_bytes(serialization.Encoding.DER)
    (CERTS / "ocsp" / "request.der").write_bytes(request_der)
    (CERTS / "ocsp" / "response.der").write_bytes(response_der)
    (CERTS / "ocsp" / "response_verify.der").write_bytes(response_der)


def verify_submission() -> None:
    ca = x509.load_pem_x509_certificate((CERTS / "rootCA.crt.pem").read_bytes())
    cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ou = ca.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    expected_ids = "-".join(STUDENT_IDS)
    assert cn == f"CA-Root-{expected_ids}"
    assert ou == f"Faculty of Computer Science and Engineer - {expected_ids}"

    ca_public_key = ca.public_key()
    for path in (CERTS / "server.crt.pem", CERTS / "ocsp" / "ocsp.crt.pem"):
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        assert cert.issuer == ca.subject
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    connection = sqlite3.connect(DB_PATH)
    req_counts = dict(connection.execute("SELECT status, COUNT(*) FROM certificate_requests GROUP BY status"))
    cert_counts = dict(connection.execute("SELECT status, COUNT(*) FROM certificates GROUP BY status"))
    crl_count = connection.execute("SELECT COUNT(*) FROM crl_records").fetchone()[0]
    connection.close()
    assert req_counts == {"APPROVED": 5, "PENDING": 1, "REJECTED": 1}
    assert cert_counts == {"REVOKED": 3, "VALID": 2}
    assert crl_count == 3

    crl = x509.load_pem_x509_crl((CERTS / "crl" / "rootCA.crl.pem").read_bytes())
    assert crl.issuer == ca.subject
    assert len(crl) == 3
    ca_public_key.verify(crl.signature, crl.tbs_certlist_bytes, padding.PKCS1v15(), crl.signature_hash_algorithm)

    print("\nVERIFY OK")
    print("Root CA CN:", cn)
    print("Root CA OU:", ou)
    print("Requests:", req_counts)
    print("Certificates:", cert_counts)
    print("CRL history:", crl_count, "latest revoked:", len(crl))


def main() -> None:
    print("Rebuilding PKI for MSSV:", ", ".join(STUDENT_IDS))
    rebuild_filesystem()
    rebuild_database()
    create_ca_and_service_certificates()
    create_requests_and_demo_state()
    create_ocsp_artifacts()
    verify_submission()
    print("\nREBUILD COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()
