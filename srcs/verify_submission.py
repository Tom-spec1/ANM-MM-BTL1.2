"""Non-destructive verification of the submitted PKI demo state."""
from pathlib import Path
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ocsp import create_ocsp_response
from project_config import ROOT_CA_COMMON_NAME, ROOT_CA_ORGANIZATIONAL_UNIT, STUDENT_IDS

BASE_DIR = Path(__file__).resolve().parent.parent
DB = BASE_DIR / "database" / "pki.db"
CA_PATH = BASE_DIR / "certs" / "rootCA.crt.pem"
SERVER_PATH = BASE_DIR / "certs" / "server.crt.pem"
OCSP_CERT_PATH = BASE_DIR / "certs" / "ocsp" / "ocsp.crt.pem"
CRL_PATH = BASE_DIR / "certs" / "crl" / "rootCA.crl.pem"


def verify_signed_certificate(cert, ca):
    assert cert.issuer == ca.subject
    ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def build_ocsp_request(cert, ca):
    return ocsp.OCSPRequestBuilder().add_certificate(cert, ca, hashes.SHA1()).build()


def verify_ocsp_signature(response, responder_cert):
    responder_cert.public_key().verify(
        response.signature,
        response.tbs_response_bytes,
        padding.PKCS1v15(),
        response.signature_hash_algorithm,
    )


def main():
    ca = x509.load_pem_x509_certificate(CA_PATH.read_bytes())
    server = x509.load_pem_x509_certificate(SERVER_PATH.read_bytes())
    responder = x509.load_pem_x509_certificate(OCSP_CERT_PATH.read_bytes())

    cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    ou = ca.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
    assert cn == ROOT_CA_COMMON_NAME
    assert ou == ROOT_CA_ORGANIZATIONAL_UNIT
    assert all(mssv in cn and mssv in ou for mssv in STUDENT_IDS)

    verify_signed_certificate(server, ca)
    verify_signed_certificate(responder, ca)
    eku = responder.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku

    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    requests = connection.execute(
        "SELECT request_id, common_name, status FROM certificate_requests ORDER BY request_id"
    ).fetchall()
    certs = connection.execute(
        "SELECT request_id, serial_number, status, certificate_pem FROM certificates ORDER BY request_id"
    ).fetchall()
    crl_versions = connection.execute("SELECT COUNT(*) FROM crl_records").fetchone()[0]
    connection.close()

    assert [r["status"] for r in requests] == [
        "APPROVED", "APPROVED", "APPROVED", "APPROVED", "APPROVED", "REJECTED", "PENDING"
    ]
    assert [r["status"] for r in certs] == ["REVOKED", "REVOKED", "REVOKED", "VALID", "VALID"]
    assert crl_versions == 3

    for row in certs:
        verify_signed_certificate(x509.load_pem_x509_certificate(row["certificate_pem"].encode()), ca)

    crl = x509.load_pem_x509_crl(CRL_PATH.read_bytes())
    assert crl.issuer == ca.subject
    assert len(crl) == 3
    ca.public_key().verify(
        crl.signature,
        crl.tbs_certlist_bytes,
        padding.PKCS1v15(),
        crl.signature_hash_algorithm,
    )

    good_cert = x509.load_pem_x509_certificate(certs[3]["certificate_pem"].encode())
    revoked_cert = x509.load_pem_x509_certificate(certs[0]["certificate_pem"].encode())

    good_response = create_ocsp_response(build_ocsp_request(good_cert, ca))
    revoked_response = create_ocsp_response(build_ocsp_request(revoked_cert, ca))

    unknown_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    unknown_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unknown.test")]))
        .issuer_name(ca.subject)
        .public_key(unknown_key.public_key())
        .serial_number(0x123456789ABCDEF)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(unknown_key, hashes.SHA256())
    )
    unknown_response = create_ocsp_response(build_ocsp_request(unknown_cert, ca))

    assert good_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert good_response.certificate_status == ocsp.OCSPCertStatus.GOOD
    assert revoked_response.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert unknown_response.certificate_status == ocsp.OCSPCertStatus.UNKNOWN
    for response in (good_response, revoked_response, unknown_response):
        verify_ocsp_signature(response, responder)

    print("ALL VERIFICATIONS PASSED")
    print("Root CA CN:", cn)
    print("Root CA OU:", ou)
    print("CSR statuses: 5 APPROVED, 1 REJECTED, 1 PENDING")
    print("Certificate statuses: 2 VALID, 3 REVOKED")
    print("CRL: 3 versions; latest contains 3 revoked certificates")
    print("OCSP: GOOD / REVOKED / UNKNOWN + valid responder signature")


if __name__ == "__main__":
    main()
