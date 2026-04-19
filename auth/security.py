from fastapi import Request, HTTPException, Depends
from passlib.context import CryptContext
from database import get_db_connection

# =========================
# PASSWORDS
# =========================

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

from passlib.context import CryptContext
import hashlib

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

def verify_password(plain_password: str, password_hash: str) -> bool:
    # New (secure) hashes
    if password_hash.startswith("$pbkdf2-sha256$"):
        return pwd_context.verify(plain_password, password_hash)

    # Legacy SHA256 hashes
    legacy_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return legacy_hash == password_hash


# =========================
# API AUTH (TOKEN)
# =========================

from fastapi import Header


def get_current_user(
    authorization: str = Header(...),
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.removeprefix("Bearer ").strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,)
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return dict(user)


# =========================
# UI AUTH (COOKIE)
# =========================

def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT u.*
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,)
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401)

    return dict(user)

# =========================
# ROLE HELPERS
# =========================

def require_admin_ui(
    user = Depends(get_current_user_from_cookie),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    return user

from typing import List
from fastapi import Depends, HTTPException


def require_roles(*roles: str):
    def _role_checker(user=Depends(get_current_user_from_cookie)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403)
        return user
    return _role_checker
