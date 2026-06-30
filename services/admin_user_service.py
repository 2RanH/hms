import secrets
import sqlite3
from datetime import UTC, datetime

from auth.security import hash_password, is_valid_role
from database import get_db_connection


def create_user(
    *,
    admin_user_id: int,
    username: str,
    full_name: str,
    role: str,
    password: str | None = None,
):
    db = get_db_connection()

    if not is_valid_role(role):
        db.close()
        raise ValueError("Invalid role")

    if password is None:
        password = secrets.token_urlsafe(10)
    elif len(password) < 8:
        db.close()
        raise ValueError("Password must be at least 8 characters")

    password_hash = hash_password(password)

    try:
        cursor = db.execute(
            """
            INSERT INTO users (username, full_name, role, password_hash, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, full_name, role, password_hash, datetime.now(UTC).isoformat()),
        )
    except sqlite3.IntegrityError:
        db.close()
        raise ValueError("Username already exists")

    user_id = cursor.lastrowid

    db.execute(
        """
        INSERT INTO audit_logs (
            action,
            entity_type,
            entity_id,
            performed_by_user_id,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "create_user",
            "user",
            user_id,
            admin_user_id,
            f"username={username}, role={role}",
            datetime.now(UTC).isoformat(),
        ),
    )

    db.commit()
    db.close()

    return {
        "user_id": user_id,
        "username": username,
        "role": role,
        "password": password,
    }


def reset_user_password(
    *,
    admin_user_id: int,
    target_user_id: int,
):
    db = get_db_connection()

    new_password = secrets.token_urlsafe(10)
    password_hash = hash_password(new_password)

    result = db.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (password_hash, target_user_id),
    )

    if result.rowcount == 0:
        db.close()
        raise ValueError("User not found")

    db.execute(
        """
        INSERT INTO audit_logs (
            action,
            entity_type,
            entity_id,
            performed_by_user_id,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "reset_password",
            "user",
            target_user_id,
            admin_user_id,
            None,
            datetime.now(UTC).isoformat(),
        ),
    )

    db.commit()
    db.close()

    return {
        "user_id": target_user_id,
        "new_password": new_password,
    }
