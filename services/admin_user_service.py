from datetime import datetime
import secrets

from database import get_db_connection
from auth.security import hash_password

def create_user(
    *,
    admin_user_id: int,
    username: str,
    full_name: str,   # ← ADD
    role: str,
    password: str | None = None
):

    db = get_db_connection()

    if role not in ("admin", "reception", "doctor"):
        raise ValueError("Invalid role")

    if password is None:
        password = secrets.token_urlsafe(10)

    password_hash = hash_password(password)

    cursor = db.execute(
        """
        INSERT INTO users (username, full_name, role, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)

        """,
        (username, full_name, role, password_hash, datetime.utcnow())
    )

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
        datetime.utcnow(),
    )
)


    db.commit()

    return {
        "user_id": user_id,
        "username": username,
        "role": role,
        "password": password,
    }

def reset_user_password(
    *,
    admin_user_id: int,
    target_user_id: int
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
        (password_hash, target_user_id)
    )

    if result.rowcount == 0:
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
        datetime.utcnow(),
    )
)


    db.commit()

    return {
        "user_id": target_user_id,
        "new_password": new_password,
    }
