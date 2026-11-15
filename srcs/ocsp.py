from pathlib import Path

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from datetime import datetime, timedelta, timezone

from cryptography.x509 import ocsp
from cryptography.x509.oid import OCSPExtensionOID
BASE_DIR = Path(__file__).resolve().parent.parent

ROOT_CA_CERT = BASE_DIR / "certs" / "rootCA.crt.pem"


def load_ca_certificate():
    """
    Doc Root CA certificate.
    """

    return x509.load_pem_x509_certificate(
        ROOT_CA_CERT.read_bytes()
    )
    
def get_certificate_status(serial_number):
    """
    Kiem tra trang thai chung thu trong SQLite.
    """

    import sqlite3

    from ca import DATABASE_PATH

    # Chuan hoa Serial Number, bo cac so 0 o dau
    serial_number = (
        serial_number.strip()
        .replace(":", "")
        .upper()
        .lstrip("0")
    )

    if not serial_number:
        serial_number = "0"

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            SELECT status
            FROM certificates
            WHERE ltrim(upper(serial_number), '0') = ?
            """,
            (serial_number,)
        )

        result = cursor.fetchone()

        if result is None:
            return "UNKNOWN"

        if result[0] == "REVOKED":
            return "REVOKED"

        return "GOOD"

    finally:
        connection.close()

def process_ocsp_request(request):
    """
    Xu ly OCSP Request va tra ve trang thai chung thu.
    """

    serial_number = format(
        request.serial_number,
        "X"
    )

    status = get_certificate_status(serial_number)

    print(f"OCSP Request received: {serial_number}")
    print(f"Certificate status: {status}")

    return status

def load_ocsp_signing_material():
    """
    Doc khoa va chung thu cua OCSP Responder.
    """

    responder_cert_path = (
        BASE_DIR / "certs" / "ocsp" / "ocsp.crt.pem"
    )

    responder_key_path = (
        BASE_DIR / "private" / "ocsp" / "ocsp.key.pem"
    )

    ca_cert = load_ca_certificate()

    responder_cert = x509.load_pem_x509_certificate(
        responder_cert_path.read_bytes()
    )

    responder_private_key = serialization.load_pem_private_key(
        responder_key_path.read_bytes(),
        password=None
    )

    return ca_cert, responder_cert, responder_private_key

def get_certificate_record(serial_number):
    """
    Lay thong tin chung thu tu SQLite theo Serial Number.
    """

    import sqlite3
    from ca import DATABASE_PATH

    serial_number = (
        serial_number.strip()
        .replace(":", "")
        .upper()
        .lstrip("0")
    )

    if not serial_number:
        serial_number = "0"

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            SELECT certificate_pem, status,
                   revoked_at, revocation_reason
            FROM certificates
            WHERE ltrim(upper(serial_number), '0') = ?
            """,
            (serial_number,)
        )

        return cursor.fetchone()

    finally:
        connection.close()
        

def create_ocsp_response(request):
    """
    Tao OCSP Response va ky bang khoa rieng OCSP Responder.
    Ho tro GOOD, REVOKED va UNKNOWN.
    """
    serial_number = format(request.serial_number, "X")
    record = get_certificate_record(serial_number)
    ca_cert, responder_cert, responder_key = load_ocsp_signing_material()

    this_update = datetime.now(timezone.utc)
    next_update = this_update + timedelta(days=1)

    builder = ocsp.OCSPResponseBuilder()

    if record is None:
        status = "UNKNOWN"

        builder = builder.add_response_by_hash(
            issuer_name_hash=request.issuer_name_hash,
            issuer_key_hash=request.issuer_key_hash,
            serial_number=request.serial_number,
            algorithm=request.hash_algorithm,
            cert_status=ocsp.OCSPCertStatus.UNKNOWN,
            this_update=this_update,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None
        )

    else:
        certificate_pem, status, revoked_at, revocation_reason_db = record

        target_cert = x509.load_pem_x509_certificate(
            certificate_pem.encode("utf-8")
        )

        if status == "REVOKED":
            cert_status = ocsp.OCSPCertStatus.REVOKED

            revocation_time = datetime.strptime(
                revoked_at,
                "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)

            revocation_reason = x509.ReasonFlags.key_compromise

        else:
            cert_status = ocsp.OCSPCertStatus.GOOD
            revocation_time = None
            revocation_reason = None

        builder = builder.add_response(
            cert=target_cert,
            issuer=ca_cert,
            algorithm=request.hash_algorithm,
            cert_status=cert_status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason
        )

    builder = builder.responder_id(
        ocsp.OCSPResponderEncoding.HASH,
        responder_cert
    )

    builder = builder.certificates([responder_cert])

    try:
        nonce_extension = request.extensions.get_extension_for_oid(
            OCSPExtensionOID.NONCE
        )
        builder = builder.add_extension(
            nonce_extension.value,
            critical=False
        )
    except x509.ExtensionNotFound:
        pass

    response = builder.sign(
        private_key=responder_key,
        algorithm=hashes.SHA256()
    )

    print(f"OCSP Response created for: {serial_number}")
    print(f"Certificate status: {status}")

    return response
