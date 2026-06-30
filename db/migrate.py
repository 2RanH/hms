import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from database import get_db_connection


TABLES = {
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """,
    "sessions": """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            csrf_token TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """,
    "patients": """
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
            notes TEXT,
            status TEXT,
            source TEXT,
            first_registration_date TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY (assigned_doctor_id) REFERENCES users(id)
        )
    """,
    "assignment_history": """
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
    """,
    "medical_records": """
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            record_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            record_group TEXT,
            updated_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id)
        )
    """,
    "medical_record_attachments": """
        CREATE TABLE IF NOT EXISTS medical_record_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            record_group TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            content_type TEXT,
            uploaded_by_user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (uploaded_by_user_id) REFERENCES users(id)
        )
    """,
    "payments": """
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
    """,
    "notifications": """
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            patient_id INTEGER,
            message TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
    """,
    "audit_logs": """
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
    """,
    "costs": """
        CREATE TABLE IF NOT EXISTS costs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            details TEXT,
            amount REAL,
            created_by_user_id INTEGER,
            created_at TEXT,
            FOREIGN KEY (created_by_user_id) REFERENCES users(id)
        )
    """,
}


COLUMNS = {
    "users": [
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
    ],
    "sessions": [
        ("csrf_token", "TEXT"),
    ],
    "patients": [
        ("notes", "TEXT"),
        ("status", "TEXT"),
        ("source", "TEXT"),
        ("first_registration_date", "TEXT"),
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
    ],
    "medical_records": [
        ("record_group", "TEXT"),
        ("updated_at", "TEXT"),
    ],
    "notifications": [
        ("patient_id", "INTEGER"),
    ],
}


INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_patients_active_id ON patients(is_active, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(name)",
    "CREATE INDEX IF NOT EXISTS idx_patients_surname ON patients(surname)",
    "CREATE INDEX IF NOT EXISTS idx_patients_father_name ON patients(father_name)",
    "CREATE INDEX IF NOT EXISTS idx_patients_phone ON patients(phone)",
    "CREATE INDEX IF NOT EXISTS idx_patients_assigned_doctor ON patients(assigned_doctor_id)",
]


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return any(row["name"] == column_name for row in cursor.fetchall())


def migrate():
    conn = get_db_connection()
    cursor = conn.cursor()

    for sql in TABLES.values():
        cursor.execute(sql)

    for table_name, columns in COLUMNS.items():
        for column_name, column_definition in columns:
            if not column_exists(cursor, table_name, column_name):
                cursor.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
                )

    for sql in INDEXES:
        cursor.execute(sql)

    cursor.execute("UPDATE users SET is_active = 1 WHERE is_active IS NULL")
    cursor.execute("UPDATE patients SET is_active = 1 WHERE is_active IS NULL")
    cursor.execute(
        """
        UPDATE medical_records
        SET record_group = CAST(patient_id AS TEXT) || '-' || CAST(created_by_user_id AS TEXT) || '-' || created_at
        WHERE record_group IS NULL OR record_group = ''
        """
    )
    cursor.execute(
        """
        UPDATE notifications
        SET patient_id = (
            SELECT patients.id
            FROM patients
            WHERE notifications.message = 'Patient ' || patients.name || ' ' || patients.surname || ' reassigned to you'
            LIMIT 1
        )
        WHERE message LIKE 'Patient % reassigned to you'
        AND EXISTS (
            SELECT 1
            FROM patients
            WHERE notifications.message = 'Patient ' || patients.name || ' ' || patients.surname || ' reassigned to you'
        )
        """
    )
    cursor.execute(
        """
        UPDATE notifications
        SET patient_id = (
            SELECT assignment_history.patient_id
            FROM assignment_history
            WHERE assignment_history.assigned_doctor_id = notifications.user_id
            AND assignment_history.changed_at = notifications.created_at
            LIMIT 1
        )
        WHERE patient_id IS NULL
        AND message LIKE 'Patient % reassigned to you'
        """
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    migrate()
