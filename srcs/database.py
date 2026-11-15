
import sqlite3
from pathlib import Path

# Xác định thư mục gốc của dự án
BASE_DIR = Path(__file__).resolve().parent.parent

# Đường dẫn đến database và file schema
DATABASE_PATH = BASE_DIR / "database" / "pki.db"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"


def get_connection():
    """Tạo kết nối đến SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    """Khởi tạo database từ file schema.sql."""

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Không tìm thấy file schema: {SCHEMA_PATH}"
        )

    with get_connection() as connection:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        connection.executescript(schema)

    print("Database initialized successfully!")
    print(f"Database location: {DATABASE_PATH}")


if __name__ == "__main__":
    initialize_database()
