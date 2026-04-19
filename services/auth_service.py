import uuid
from datetime import datetime, UTC

from fastapi import HTTPException

from database import get_db_connection
from auth.security import verify_password


def authenticate_user_and_return_token(username: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = str(uuid.uuid4())

    cursor.execute(
        """
        INSERT INTO sessions (token, user_id, created_at)
        VALUES (?, ?, ?)
        """,
        (token, user["id"], datetime.now(UTC).isoformat())
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
