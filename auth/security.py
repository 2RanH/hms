import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import Depends, Header, HTTPException, Request
from passlib.context import CryptContext
from dotenv import load_dotenv

from database import get_db_connection


load_dotenv(Path(__file__).resolve().parent.parent / ".env")

VALID_ROLES = ("admin", "reception", "doctor")
SESSION_COOKIE_NAME = "session_token"
SESSION_DAYS = int(os.getenv("HSM_SESSION_DAYS", "30"))
SESSION_MAX_AGE_SECONDS = SESSION_DAYS * 24 * 60 * 60
COOKIE_SECURE = os.getenv("HSM_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    if password_hash.startswith("$pbkdf2-sha256$"):
        return pwd_context.verify(plain_password, password_hash)

    legacy_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return legacy_hash == password_hash


def is_valid_role(role: str) -> bool:
    return role in VALID_ROLES


def parse_session_created_at(value: str):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def is_session_expired(created_at: str) -> bool:
    parsed = parse_session_created_at(created_at)
    if not parsed:
        return True
    return datetime.now(UTC) - parsed > timedelta(seconds=SESSION_MAX_AGE_SECONDS)


def delete_session(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()


def get_user_by_session_token(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            u.*,
            s.created_at AS session_created_at,
            s.csrf_token AS csrf_token
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        AND COALESCE(u.is_active, 1) = 1
        """,
        (token,),
    )

    user = cursor.fetchone()
    conn.close()

    if not user:
        return None

    user_dict = dict(user)
    if is_session_expired(user_dict["session_created_at"]):
        delete_session(token)
        return None

    return user_dict


def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization.removeprefix("Bearer ").strip()
    user = get_user_by_session_token(token)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return user


def get_current_user_from_cookie(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401)

    user = get_user_by_session_token(token)
    if not user:
        raise HTTPException(status_code=401)

    return user


def get_or_create_csrf_token(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return ""

    user = get_user_by_session_token(token)
    if not user:
        return ""

    csrf_token = user.get("csrf_token")
    if csrf_token:
        return csrf_token

    csrf_token = secrets.token_urlsafe(32)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE sessions SET csrf_token = ? WHERE token = ?",
        (csrf_token, token),
    )
    conn.commit()
    conn.close()
    return csrf_token


async def require_csrf(request: Request):
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        raise HTTPException(status_code=401)

    user = get_user_by_session_token(session_token)
    if not user:
        raise HTTPException(status_code=401)

    expected_token = user.get("csrf_token") or get_or_create_csrf_token(request)
    form = await request.form()
    submitted_token = form.get("csrf_token")

    if not expected_token or not secrets.compare_digest(expected_token, submitted_token or ""):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def set_session_cookie(response, token: str):
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_MAX_AGE_SECONDS,
    )


def require_admin_ui(user=Depends(get_current_user_from_cookie)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    return user


def require_roles(*roles: str):
    def _role_checker(user=Depends(get_current_user_from_cookie)):
        if user["role"] not in roles:
            raise HTTPException(status_code=403)
        return user

    return _role_checker
