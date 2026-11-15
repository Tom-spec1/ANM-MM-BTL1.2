from pathlib import Path
import sqlite3
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "pki.db"
CA_PATH = BASE_DIR / "certs" / "rootCA.crt.pem"


def connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def load_ca():
    return x509.load_pem_x509_certificate(CA_PATH.read_bytes())


def verify_cert(cert, ca=None):
    ca = ca or load_ca()
    assert cert.issuer == ca.subject
    ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return True
