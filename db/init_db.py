import sys
from pathlib import Path

# Add project root to Python path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from database import get_db_connection

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        surname TEXT NOT NULL,
        father_name TEXT NOT NULL,
        date_of_birth TEXT NOT NULL,
        gender TEXT NOT NULL,
        region TEXT NOT NULL,
        phone TEXT NOT NULL,
        assigned_doctor_id INTEGER NOT NULL,
        assigned_examination TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (assigned_doctor_id) REFERENCES users(id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assignment_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        assigned_doctor_id INTEGER,
        assigned_examination TEXT,
        changed_by_user_id INTEGER NOT NULL,
        changed_at TEXT NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (assigned_doctor_id) REFERENCES users(id),
        FOREIGN KEY (changed_by_user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS medical_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        record_type TEXT NOT NULL,
        content TEXT NOT NULL,
        created_by_user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (created_by_user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        payment_type TEXT NOT NULL,
        amount REAL NOT NULL,
        received_by_user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (patient_id) REFERENCES patients(id),
        FOREIGN KEY (received_by_user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        performed_by_user_id INTEGER NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (performed_by_user_id) REFERENCES users(id)
    )
    """)





    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
from auth.security import hash_password
from datetime import datetime, UTC

def create_admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    )
    if cursor.fetchone():
        conn.close()
        return

    cursor.execute("""
        INSERT INTO users (username, password_hash, full_name, role, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        "admin",
        hash_password("admin123"),
        "System Administrator",
        "admin",
        datetime.now(UTC).isoformat()
    ))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    create_admin()

