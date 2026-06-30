import secrets
from datetime import datetime, UTC

from fastapi import HTTPException

from database import get_db_connection
from auth.security import verify_password


def authenticate_user_and_return_token(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        AND COALESCE(is_active, 1) = 1
        """,
        (username,)
    )
    user = cursor.fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)

    cursor.execute(
        """
        INSERT INTO sessions (token, user_id, created_at, csrf_token)
        VALUES (?, ?, ?, ?)
        """,
        (token, user["id"], datetime.now(UTC).isoformat(), csrf_token)
    )

    conn.commit()
    conn.close()

    return {
        "token": token,
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
    }
