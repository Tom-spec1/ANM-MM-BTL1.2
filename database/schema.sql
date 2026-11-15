
PRAGMA foreign_keys = ON;

-- 1. Certificate Signing Requests
CREATE TABLE IF NOT EXISTS certificate_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    common_name TEXT NOT NULL,
    subject TEXT NOT NULL,
    csr_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TEXT,
    rejection_reason TEXT
);

-- 2. Issued certificates
CREATE TABLE IF NOT EXISTS certificates (
    serial_number TEXT PRIMARY KEY,
    request_id INTEGER,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'VALID'
        CHECK (status IN ('VALID', 'REVOKED')),
    issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT,
    revocation_reason TEXT,

    FOREIGN KEY (request_id)
        REFERENCES certificate_requests(request_id)
);

-- 3. Certificate Revocation Lists
CREATE TABLE IF NOT EXISTS crl_records (
    crl_number INTEGER PRIMARY KEY,
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_pem TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for searching certificates
CREATE INDEX IF NOT EXISTS idx_certificates_status
ON certificates(status);

CREATE INDEX IF NOT EXISTS idx_certificates_subject
ON certificates(subject);

CREATE INDEX IF NOT EXISTS idx_requests_status
ON certificate_requests(status);
