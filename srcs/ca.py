import os
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from getpass import getpass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

from project_config import DEMO_ROOT_CA_PASSPHRASE

# Xac dinh thu muc goc du an
BASE_DIR = Path(__file__).resolve().parent.parent

# Duong dan cac thanh phan CA
ROOT_CA_CERT = BASE_DIR / "certs" / "rootCA.crt.pem"
ROOT_CA_KEY = BASE_DIR / "private" / "rootCA.key.pem"
CA_SERIAL = BASE_DIR / "certs" / "rootCA.crt.srl"

DATABASE_PATH = BASE_DIR / "database" / "pki.db"


def _root_ca_passphrase(prompt=True):
    """Return Root CA passphrase from env, or ask interactively."""
    value = os.getenv("PKI_ROOT_CA_PASSPHRASE")
    if value:
        return value
    if prompt:
        return getpass("Enter Root CA private key passphrase: ")
    return DEMO_ROOT_CA_PASSPHRASE



def validate_csr(csr_path):
    """Kiem tra tinh hop le cua CSR."""

    result = subprocess.run(
        [
            "openssl",
            "req",
            "-in", str(csr_path),
            "-verify",
            "-noout"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise ValueError(f"CSR khong hop le: {result.stderr}")

    return True


def issue_certificate(csr_path, output_path, extension_path):
    """Ky CSR bang Root CA va tao chung thu X.509."""

    validate_csr(csr_path)

    required_files = [
        ROOT_CA_CERT,
        ROOT_CA_KEY,
        CA_SERIAL,
        Path(csr_path),
        Path(extension_path)
    ]

    for file_path in required_files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Khong tim thay file: {file_path}"
            )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "openssl", "x509",
        "-req",
        "-in", str(csr_path),
        "-CA", str(ROOT_CA_CERT),
        "-CAkey", str(ROOT_CA_KEY),
        "-CAserial", str(CA_SERIAL),
        "-out", str(output_path),
        "-days", "365",
        "-sha256",
        "-extfile", str(extension_path),
        "-extensions", "server_cert"
    ]

    # Uu tien passphrase tu bien moi truong de test/rebuild tu dong.
    # Neu khong co, OpenSSL se hoi tren console nhu ban goc.
    env_passphrase = os.getenv("PKI_ROOT_CA_PASSPHRASE")
    if env_passphrase:
        command.extend(["-passin", "env:PKI_ROOT_CA_PASSPHRASE"])

    result = subprocess.run(command, env=os.environ.copy())

    if result.returncode != 0:
        raise RuntimeError(
            "Loi khi ky chung thu bang OpenSSL."
        )

    print("Certificate issued successfully!")
    print(f"Certificate location: {output_path}")

    return output_path


def save_certificate(certificate_path, request_id=None, connection=None):
    """Luu thong tin chung thu vao SQLite."""

    certificate_path = Path(certificate_path)

    if not certificate_path.exists():
        raise FileNotFoundError(
            f"Khong tim thay chung thu: {certificate_path}"
        )

    certificate_pem = certificate_path.read_text(
        encoding="utf-8"
    )

    result = subprocess.run(
        [
            "openssl", "x509",
            "-in", str(certificate_path),
            "-noout",
            "-serial",
            "-subject",
            "-issuer",
            "-startdate",
            "-enddate"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    cert_info = {}

    for line in result.stdout.splitlines():
        key, value = line.split("=", 1)
        cert_info[key] = value.strip()

    serial_number = cert_info["serial"].replace(":", "").upper()
    subject = cert_info["subject"]
    issuer = cert_info["issuer"]

    def convert_date(value):
        dt = datetime.strptime(
            value,
            "%b %d %H:%M:%S %Y %Z"
        )
        return dt.replace(tzinfo=timezone.utc).isoformat()

    not_before = convert_date(cert_info["notBefore"])
    not_after = convert_date(cert_info["notAfter"])

    # Chi tao connection moi neu khong duoc truyen connection vao
    owns_connection = connection is None

    if owns_connection:
        connection = sqlite3.connect(DATABASE_PATH)

    try:
        connection.execute(
            """
            INSERT INTO certificates (
                serial_number,
                request_id,
                subject,
                issuer,
                certificate_pem,
                not_before,
                not_after,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'VALID')
            """,
            (
                serial_number,
                request_id,
                subject,
                issuer,
                certificate_pem,
                not_before,
                not_after
            )
        )

        if owns_connection:
            connection.commit()

    finally:
        if owns_connection:
            connection.close()

    print("Certificate information saved to database!")
    print(f"Serial number: {serial_number}")

def submit_certificate_request(csr_path):
    """
    Tiep nhan CSR va luu yeu cau vao SQLite.
    Trang thai mac dinh: PENDING.
    """

    csr_path = Path(csr_path)

    if not csr_path.exists():
        raise FileNotFoundError(
            f"Khong tim thay CSR: {csr_path}"
        )

    # Kiem tra chu ky CSR
    validate_csr(csr_path)

    # Doc noi dung CSR
    csr_pem = csr_path.read_text(encoding="utf-8")

    # Phan tich thong tin CSR
    csr = x509.load_pem_x509_csr(
        csr_pem.encode("utf-8")
    )

    # Lay Common Name
    common_names = csr.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if not common_names:
        raise ValueError(
            "CSR khong co Common Name (CN)."
        )

    common_name = common_names[0].value

    # Lay Subject
    subject = csr.subject.rfc4514_string()

    # Luu yeu cau vao SQLite
    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            INSERT INTO certificate_requests (
                common_name,
                subject,
                csr_pem,
                status
            )
            VALUES (?, ?, ?, 'PENDING')
            """,
            (
                common_name,
                subject,
                csr_pem
            )
        )

        request_id = cursor.lastrowid
        connection.commit()

    finally:
        connection.close()

    print("Certificate request submitted successfully!")
    print(f"Request ID: {request_id}")
    print(f"Common Name: {common_name}")
    print("Status: PENDING")

    return request_id

def approve_request(request_id, extension_path, output_path):
    """
    Phe duyet CSR va cap chung thu.
    """

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        request = connection.execute(
            """
            SELECT *
            FROM certificate_requests
            WHERE request_id = ?
            """,
            (request_id,)
        ).fetchone()

        if request is None:
            raise ValueError("Khong tim thay yeu cau.")

        if request["status"] != "PENDING":
            raise ValueError("Yeu cau khong o trang thai PENDING.")

        # Tao file CSR tam thoi tu noi dung trong database
        csr_path = BASE_DIR / "requests" / f"approved_{request_id}.csr.pem"
        csr_path.write_text(request["csr_pem"], encoding="utf-8")

    finally:
        connection.close()

    # Ky CSR bang Root CA
    certificate_path = issue_certificate(
        csr_path,
        output_path,
        extension_path
    )

    # Luu thong tin chung thu va cap nhat trang thai
    connection = sqlite3.connect(DATABASE_PATH)

    try:
        connection.execute(
            """
            UPDATE certificate_requests
            SET status = 'APPROVED',
                processed_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
              AND status = 'PENDING'
            """,
            (request_id,)
        )

        if connection.total_changes == 0:
            raise ValueError("Yeu cau da duoc xu ly.")

        # Luu chung thu, lien ket voi request_id
        save_certificate(
    certificate_path,
    request_id,
    connection=connection
)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print(f"Request {request_id} approved successfully!")


def reject_request(request_id, reason):
    """
    Tu choi yeu cau cap chung thu.
    """

    if not reason or not reason.strip():
        raise ValueError("Phai cung cap ly do tu choi.")

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            UPDATE certificate_requests
            SET status = 'REJECTED',
                processed_at = CURRENT_TIMESTAMP,
                rejection_reason = ?
            WHERE request_id = ?
              AND status = 'PENDING'
            """,
            (reason.strip(), request_id)
        )

        if cursor.rowcount == 0:
            raise ValueError(
                "Khong tim thay yeu cau PENDING."
            )

        connection.commit()

    finally:
        connection.close()

    print(f"Request {request_id} rejected successfully!")
def revoke_certificate(serial_number, reason):
    """
    Thu hoi chung thu theo Serial Number.
    """

    if not serial_number or not serial_number.strip():
        raise ValueError("Serial Number khong duoc de trong.")

    if not reason or not reason.strip():
        raise ValueError("Phai cung cap ly do thu hoi.")

    serial_number = serial_number.replace(":", "").strip().upper()

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            UPDATE certificates
            SET status = 'REVOKED',
                revoked_at = CURRENT_TIMESTAMP,
                revocation_reason = ?
            WHERE serial_number = ?
              AND status = 'VALID'
            """,
            (reason.strip(), serial_number)
        )

        if cursor.rowcount == 0:
            raise ValueError(
                "Khong tim thay chung thu VALID voi Serial Number nay."
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print("Certificate revoked successfully!")
    print(f"Serial Number: {serial_number}")
    print(f"Reason: {reason.strip()}")

def generate_crl():
    """
    Tao Certificate Revocation List (CRL)
    va ky CRL bang Root CA.
    """

    # Duong dan file CRL
    crl_dir = BASE_DIR / "certs" / "crl"
    crl_dir.mkdir(parents=True, exist_ok=True)

    crl_path = crl_dir / "rootCA.crl.pem"

    # Doc Root CA certificate
    ca_cert = x509.load_pem_x509_certificate(
        ROOT_CA_CERT.read_bytes()
    )

    # Doc Root CA private key
    ca_password = _root_ca_passphrase(prompt=True)

    ca_private_key = serialization.load_pem_private_key(
        ROOT_CA_KEY.read_bytes(),
        password=ca_password.encode("utf-8")
    )
    # Lay danh sach chung thu da bi thu hoi
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    try:
        revoked_certificates = connection.execute(
            """
            SELECT serial_number, revoked_at
            FROM certificates
            WHERE status = 'REVOKED'
            """
        ).fetchall()

    finally:
        connection.close()

    # Tao CRL builder
    now = datetime.now(timezone.utc)

    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )

    # Them cac chung thu da bi thu hoi vao CRL
    for certificate in revoked_certificates:

        revoked_at = datetime.strptime(
            certificate["revoked_at"],
            "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(
                int(certificate["serial_number"], 16)
            )
            .revocation_date(revoked_at)
            .build()
        )

        crl_builder = crl_builder.add_revoked_certificate(
            revoked_cert
        )

    # Ky CRL bang Root CA private key
    crl = crl_builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )

    # Luu CRL vao file PEM
    crl_pem = crl.public_bytes(
        serialization.Encoding.PEM
    )

    crl_path.write_bytes(crl_pem)
    # Luu thong tin CRL vao SQLite
    this_update = crl.last_update_utc.isoformat()
    next_update = crl.next_update_utc.isoformat()

    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.execute(
            """
            SELECT COALESCE(MAX(crl_number), 0) + 1
            FROM crl_records
            """
        )

        crl_number = cursor.fetchone()[0]

        connection.execute(
            """
            INSERT INTO crl_records (
                crl_number,
                this_update,
                next_update,
                crl_pem
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                crl_number,
                this_update,
                next_update,
                crl_pem.decode("utf-8")
            )
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    print("CRL generated successfully!")
    print(f"CRL location: {crl_path}")
    print(f"Revoked certificates: {len(revoked_certificates)}")

    return crl_path