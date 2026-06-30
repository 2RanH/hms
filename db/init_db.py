import sys
from pathlib import Path
from datetime import datetime, UTC

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from auth.security import hash_password
from database import get_db_connection
from db.migrate import migrate


def create_admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",),
    )
    if cursor.fetchone():
        conn.close()
        return

    cursor.execute(
        """
        INSERT INTO users (username, password_hash, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "admin",
            hash_password("admin123"),
            "System Administrator",
            "admin",
            datetime.now(UTC).isoformat(),
        ),
    )

    conn.commit()
    conn.close()


def init_db():
    migrate()


if __name__ == "__main__":
    init_db()
    create_admin()
