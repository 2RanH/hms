from fastapi import (
    FastAPI,
    Request,
    Form,
    HTTPException,
    Depends,
    status,
    File,
    UploadFile,
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime
from datetime import timedelta
from pathlib import Path
import mimetypes
import os
import re
import time
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

def now_local():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def parse_local_datetime(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=None)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value).replace(tzinfo=None)
    except ValueError:
        return None


def is_record_editable(created_at):
    created = parse_local_datetime(created_at)
    if not created:
        return False
    delta = datetime.now() - created
    return delta.total_seconds() <= EDIT_WINDOW_HOURS * 60 * 60


def safe_original_filename(filename):
    name = Path(filename or "attachment").name
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:180] or "attachment"


MAX_ATTACHMENT_BYTES = int(os.getenv("HSM_MAX_ATTACHMENT_MB", "10")) * 1024 * 1024
MAX_ATTACHMENTS_PER_RECORD = int(os.getenv("HSM_MAX_ATTACHMENTS_PER_RECORD", "10"))
ALLOWED_ATTACHMENT_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".pdf",
    ".doc", ".docx",
    ".xls", ".xlsx",
    ".txt",
}


def validate_attachment_name(filename):
    original_filename = safe_original_filename(filename)
    extension = Path(original_filename).suffix.lower()
    if extension not in ALLOWED_ATTACHMENT_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported attachment type",
        )
    return original_filename, extension


def save_upload_with_limit(upload, target_path):
    written = 0
    with target_path.open("wb") as output:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_ATTACHMENT_BYTES:
                output.close()
                try:
                    target_path.unlink()
                except OSError:
                    pass
                raise HTTPException(
                    status_code=400,
                    detail=f"Attachment is too large. Max size is {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB",
                )
            output.write(chunk)
    return written


def save_uploaded_attachments(files, patient_id, record_group, user_id, cursor):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    saved_count = 0
    valid_uploads = [upload for upload in (files or []) if upload and upload.filename]
    if len(valid_uploads) > MAX_ATTACHMENTS_PER_RECORD:
        raise HTTPException(
            status_code=400,
            detail=f"Too many attachments. Max allowed is {MAX_ATTACHMENTS_PER_RECORD}",
        )

    for upload in valid_uploads:
        original_filename, extension = validate_attachment_name(upload.filename)
        stored_filename = f"{uuid.uuid4().hex}{extension}"
        target_path = UPLOAD_DIR / stored_filename

        save_upload_with_limit(upload, target_path)

        cursor.execute(
            """
            INSERT INTO medical_record_attachments (
                patient_id,
                record_group,
                stored_filename,
                original_filename,
                content_type,
                uploaded_by_user_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                patient_id,
                record_group,
                stored_filename,
                original_filename,
                upload.content_type,
                user_id,
                now_local(),
            ),
        )
        saved_count += 1

    return saved_count

from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime, UTC
import uuid

from database import get_db_connection
from services.auth_service import authenticate_user_and_return_token
from routes.admin_users import router as admin_users_router
from auth.security import (
    get_current_user_from_cookie,
    require_roles,
    require_csrf,
    verify_password,
    hash_password,
    is_valid_role,
    set_session_cookie,
    get_or_create_csrf_token,
)


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(admin_users_router)

LOGIN_ATTEMPT_WINDOW_SECONDS = int(os.getenv("HSM_LOGIN_WINDOW_SECONDS", "900"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("HSM_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_ATTEMPTS = {}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if os.getenv("HSM_ENABLE_HSTS", "false").lower() in ("1", "true", "yes"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def login_rate_key(request: Request, username: str):
    forwarded_for = request.headers.get("x-forwarded-for")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else None
    if not client_ip and request.client:
        client_ip = request.client.host
    return (client_ip or "unknown", username.strip().lower())


def is_login_limited(key):
    now = time.time()
    attempts = [
        attempt_time
        for attempt_time in LOGIN_ATTEMPTS.get(key, [])
        if now - attempt_time < LOGIN_ATTEMPT_WINDOW_SECONDS
    ]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(key):
    now = time.time()
    attempts = [
        attempt_time
        for attempt_time in LOGIN_ATTEMPTS.get(key, [])
        if now - attempt_time < LOGIN_ATTEMPT_WINDOW_SECONDS
    ]
    attempts.append(now)
    LOGIN_ATTEMPTS[key] = attempts


def clear_failed_logins(key):
    LOGIN_ATTEMPTS.pop(key, None)

templates = Jinja2Templates(directory="templates")
templates.env.globals["csrf_token"] = get_or_create_csrf_token

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads" / "medical_records"
EDIT_WINDOW_HOURS = 48
MEDICAL_RECORD_FIELDS = [
    ("shikayetler", "Şikayətlər"),
    ("anamnez", "Anamnez"),
    ("nevrostatus", "Nevrostatus"),
    ("muayine", "Müayinə"),
    ("diaqnoz", "Diaqnoz"),
    ("mualice", "Müalicə"),
]
MEDICAL_RECORD_TYPE_LABELS = {
    "ЕћikayЙ™tlЙ™r": "Şikayətlər",
    "MГјayinЙ™": "Müayinə",
    "MГјalicЙ™": "Müalicə",
}
MEDICAL_RECORD_FIELDS = [
    ("shikayetler", "Şikayətlər"),
    ("anamnez", "Anamnez"),
    ("nevrostatus", "Nevrostatus"),
    ("muayine", "Müayinə"),
    ("diaqnoz", "Diaqnoz"),
    ("mualice", "Müalicə"),
]
MEDICAL_RECORD_TYPE_LABELS.update({
    "ЕћikayЙ™tlЙ™r": "Şikayətlər",
    "Р•С›ikayР™в„ўtlР™в„ўr": "Şikayətlər",
    "MГјayinЙ™": "Müayinə",
    "MР“СayinР™в„ў": "Müayinə",
    "MГјalicЙ™": "Müalicə",
    "MР“СalicР™в„ў": "Müalicə",
    "ЖЏlavЙ™lЙ™r": "Əlavələr",
})


def medical_record_label(record_type):
    return MEDICAL_RECORD_TYPE_LABELS.get(record_type, record_type)

def inject_notification_count(request: Request):
    unread_notifications = 0

    token = request.cookies.get("session_token")

    if token:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT users.id, users.role
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token = ?
            """, (token,))

            user = cursor.fetchone()

            if user and user["role"] == "doctor":
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM notifications
                    WHERE user_id = ?
                    AND is_read = 0
                """, (user["id"],))

                unread_notifications = cursor.fetchone()["count"]

            conn.close()

        except:
            pass

    return {
        "unread_notifications": unread_notifications
    }

templates.env.globals["inject_notification_count"] = inject_notification_count

# ======================================================
# GLOBAL UI AUTH HANDLER
# ======================================================

@app.exception_handler(HTTPException)
def ui_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse(url="/login")
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return HTMLResponse(
        content=f"<h2>{exc.status_code}</h2><p>{detail}</p>",
        status_code=exc.status_code,
    )

# ======================================================
# AUDIT LOG HELPER
# ======================================================

def log_action(cursor, action, entity_type, entity_id, user_id, details=None):
    cursor.execute(
        """
        INSERT INTO audit_logs (
            action, entity_type, entity_id,
            performed_by_user_id, details, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            action,
            entity_type,
            entity_id,
            user_id,
            details,
            now_local(),
        ),
    )

# ======================================================
# MODELS
# ======================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    full_name: str
    role: str

class CreatePatientRequest(BaseModel):
    name: str
    surname: str
    father_name: str
    date_of_birth: str
    gender: str
    region: str
    phone: str
    assigned_doctor_id: int
    assigned_examination: str | None = None

class MedicalRecordRequest(BaseModel):
    record_type: str
    content: str

class PaymentRequest(BaseModel):
    payment_type: str
    amount: float

class ReassignRequest(BaseModel):
    assigned_doctor_id: int | None = None
    assigned_examination: str | None = None

# ======================================================
# AUTH
# ======================================================


# ======================================================
# ROLE PINGS (API)
# ======================================================

@app.get("/admin/ping")
def admin_ping(user=Depends(require_roles("admin"))):
    return {"status": "admin ok"}

@app.get("/doctor/ping")
def doctor_ping(user=Depends(require_roles("doctor"))):
    return {"status": "doctor ok"}

@app.get("/reception/ping")
def reception_ping(user=Depends(require_roles("reception"))):
    return {"status": "reception ok"}

# ======================================================
# UI LOGIN / LOGOUT
# ======================================================

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/ui/login")
def ui_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    rate_key = login_rate_key(request, username)
    if is_login_limited(rate_key):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Too many failed attempts. Try again later."},
            status_code=429,
        )

    try:
        result = authenticate_user_and_return_token(username, password)
    except HTTPException:
        record_failed_login(rate_key)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
        )

    clear_failed_logins(rate_key)

    role = result["role"]

    if role == "admin":
        redirect_url = "/admin"
    elif role == "reception":
        redirect_url = "/reception"
    elif role == "doctor":
        redirect_url = "/doctor"
    else:
        redirect_url = "/login"

    conn = get_db_connection()
    cursor = conn.cursor()
    log_action(
        cursor,
        action="login",
        entity_type="user",
        entity_id=result["id"],
        user_id=result["id"],
        details="User logged in"
    )
    conn.commit()
    conn.close()

    response = RedirectResponse(url=redirect_url, status_code=302)
    set_session_cookie(response, result["token"])
    return response

@app.get("/logout")
def logout(
    request: Request,
    user=Depends(get_current_user_from_cookie),
):
    token = request.cookies.get("session_token")
    if token:
        conn = get_db_connection()
        cursor = conn.cursor()
        log_action(
            cursor,
            action="logout",
            entity_type="user",
            entity_id=user["id"],
            user_id=user["id"],
            details="User logged out"
        )
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()

    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("session_token")
    return response

# ======================================================
# ROOT REDIRECT
# ======================================================

@app.get("/")
def root_redirect(user=Depends(get_current_user_from_cookie)):
    role = user["role"]

    if role == "admin":
        return RedirectResponse("/admin", status_code=302)
    if role == "reception":
        return RedirectResponse("/reception", status_code=302)
    if role == "doctor":
        return RedirectResponse("/doctor", status_code=302)

    return RedirectResponse("/login", status_code=302)

# ======================================================
# ADMIN UI
# ======================================================

@app.get("/admin", response_class=HTMLResponse)
def admin_home(
    request: Request,
    user=Depends(get_current_user_from_cookie),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    return templates.TemplateResponse(
        "admin_home.html",
        {"request": request, "user": user},
    )

@app.get("/ui/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    user=Depends(get_current_user_from_cookie),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, full_name, role, created_at
        FROM users
        WHERE is_active = 1
        ORDER BY id
    """)

    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "user": user, "users": users},
    )

@app.get("/ui/admin/users/{user_id}/edit", response_class=HTMLResponse)
def admin_edit_user_page(
    user_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    conn.close()

    if not target:
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        "admin_edit_user.html",
        {
            "request": request,
            "user": user,
            "target": dict(target)
        }
    )

@app.post("/ui/admin/users/{user_id}/edit")
def admin_edit_user_submit(
    user_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    username: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    password: str = Form(None)
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)
    if not is_valid_role(role):
        raise HTTPException(status_code=400, detail="Invalid role")
    if password and len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    conn = get_db_connection()
    cursor = conn.cursor()

    if password:
        cursor.execute("""
            UPDATE users
            SET username = ?, full_name = ?, role = ?, password_hash = ?
            WHERE id = ?
        """, (
            username,
            full_name,
            role,
            hash_password(password),
            user_id
        ))
    else:
        cursor.execute("""
            UPDATE users
            SET username = ?, full_name = ?, role = ?
            WHERE id = ?
        """, (
            username,
            full_name,
            role,
            user_id
        ))

    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/ui/admin/users",
        status_code=302
    )


@app.post("/ui/admin/users/{user_id}/delete")
def admin_delete_user(
    user_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, full_name FROM users WHERE id = ?",
        (user_id,)
    )
    u = cursor.fetchone()
    if not u:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        UPDATE users
        SET is_active = 0
        WHERE id = ?
    """, (user_id,))

    log_action(
        cursor,
        action="delete_user",
        entity_type="user",
        entity_id=user_id,
        user_id=user["id"],
        details=f"User deleted: {u['full_name']} ({u['username']})"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/ui/admin/users",
        status_code=302
    )


@app.get("/ui/admin/audit-logs", response_class=HTMLResponse)
def admin_audit_logs(
    request: Request,
    user=Depends(get_current_user_from_cookie),
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT
            audit_logs.created_at,
            users.username AS actor,
            audit_logs.action,
            audit_logs.entity_type,
            audit_logs.entity_id,
            audit_logs.details
        FROM audit_logs
        JOIN users ON users.id = audit_logs.performed_by_user_id
        ORDER BY datetime(audit_logs.created_at) DESC
        LIMIT 100
        """
    )
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "admin_audit_logs.html",
        {"request": request, "user": user, "logs": logs},
    )

@app.get("/ui/admin/payments", response_class=HTMLResponse)
def admin_payments(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    from_date: str = None,
    to_date: str = None
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses_payments = []
    where_clauses_costs = []
    params_payments = []
    params_costs = []

    if from_date:
        where_clauses_payments.append("date(payments.created_at) >= date(?)")
        where_clauses_costs.append("date(costs.created_at) >= date(?)")
        params_payments.append(from_date)
        params_costs.append(from_date)

    if to_date:
        where_clauses_payments.append("date(payments.created_at) <= date(?)")
        where_clauses_costs.append("date(costs.created_at) <= date(?)")
        params_payments.append(to_date)
        params_costs.append(to_date)

    where_sql_payments = ""
    if where_clauses_payments:
        where_sql_payments = "WHERE " + " AND ".join(where_clauses_payments)

    where_sql_costs = ""
    if where_clauses_costs:
        where_sql_costs = "WHERE " + " AND ".join(where_clauses_costs)

    query = f"""
        SELECT
            payments.created_at AS created_at,
            patients.name || ' ' || patients.surname AS entity_name,
            payments.payment_type AS payment_type,
            payments.amount AS amount,
            users.username AS received_by,
            0 AS is_cost
        FROM payments
        JOIN patients ON patients.id = payments.patient_id
        JOIN users ON users.id = payments.received_by_user_id
        {where_sql_payments}

        UNION ALL

        SELECT
            costs.created_at AS created_at,
            costs.category AS entity_name,
            costs.details AS payment_type,
            costs.amount AS amount,
            users.username AS received_by,
            1 AS is_cost
        FROM costs
        JOIN users ON users.id = costs.created_by_user_id
        {where_sql_costs}

        ORDER BY created_at DESC
    """

    cursor.execute(query, params_payments + params_costs)
    payments = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(
        "admin_payments.html",
        {
            "request": request,
            "user": user,
            "payments": payments
        }
    )


@app.get("/ui/admin/patients", response_class=HTMLResponse)
def admin_patients(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    q: str = "",
    page: int = 1
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    page_size = 25
    page = max(page, 1)
    offset = (page - 1) * page_size
    search = f"%{q.strip()}%"

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*) AS total
        FROM patients
        WHERE COALESCE(is_active, 1) = 1
        AND (
            name LIKE ?
            OR surname LIKE ?
            OR father_name LIKE ?
            OR phone LIKE ?
        )
        """,
        (search, search, search, search),
    )
    total_patients = cursor.fetchone()["total"]
    total_pages = max((total_patients + page_size - 1) // page_size, 1)
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * page_size

    cursor.execute("""
        SELECT id, name, surname, father_name, phone
        FROM patients
        WHERE COALESCE(is_active, 1) = 1
        AND (
            name LIKE ?
            OR surname LIKE ?
            OR father_name LIKE ?
            OR phone LIKE ?
        )
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (search, search, search, search, page_size, offset))

    patients = [dict(row) for row in cursor.fetchall()][:page_size]
    conn.close()

    return templates.TemplateResponse(
        "admin_patients.html",
        {
            "request": request,
            "user": user,
            "patients": patients,
            "q": q,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_patients": total_patients,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1
        }
    )


@app.get("/doctor", response_class=HTMLResponse)
def doctor_home(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    return templates.TemplateResponse(
        "doctor_home.html",
        {"request": request, "user": user}
    )

@app.get("/reception", response_class=HTMLResponse)
def reception_home(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    return templates.TemplateResponse(
        "reception_home.html",
        {"request": request, "user": user}
    )

@app.get("/admin", response_class=HTMLResponse)
def admin_home(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    return templates.TemplateResponse(
        "admin_home.html",
        {"request": request, "user": user}
    )

@app.get("/ui/doctor/patients", response_class=HTMLResponse)
def doctor_patients(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    q: str = ""
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    today = datetime.now().date()
    cursor.execute("""
        SELECT
            COALESCE(MAX(assignment_history.changed_at), patients.first_registration_date, patients.created_at) AS changed_at,

            patients.id,
            patients.name,
            patients.surname,
            patients.father_name,
            patients.date_of_birth,
            patients.phone,

            (
                SELECT MAX(created_at)
                FROM medical_records
                WHERE medical_records.patient_id = patients.id
            ) AS last_record_date

        FROM patients

        LEFT JOIN assignment_history
            ON assignment_history.patient_id = patients.id
            AND assignment_history.assigned_doctor_id = ?
        WHERE assignment_history.assigned_doctor_id = ?
        AND patients.assigned_doctor_id = ?
        AND patients.is_active = 1
        AND (
            patients.name LIKE ?
            OR patients.surname LIKE ?
            OR patients.father_name LIKE ?
            OR patients.phone LIKE ?
        )
        GROUP BY
            patients.id,
            patients.name,
            patients.surname,
            patients.father_name,
            patients.date_of_birth,
            patients.phone,
            patients.first_registration_date,
            patients.created_at
        ORDER BY datetime(changed_at) DESC, patients.id DESC
    """, (
        user["id"],
        user["id"],
        user["id"],
        f"%{q}%",
        f"%{q}%",
        f"%{q}%",
        f"%{q}%"
    ))

    all_rows = cursor.fetchall()
    visible_days = []
    rows = []
    for row in all_rows:
        day = row["changed_at"][:10]
        if day not in visible_days:
            if len(visible_days) >= 5:
                continue
            visible_days.append(day)
        if day in visible_days:
            rows.append(row)

    grouped_patients = {}

    for row in rows:

        patient = dict(row)

        visit_day = patient["changed_at"][:10]

        last_record = patient.get("last_record_date")

        if not last_record:
            patient["record_status"] = "none"

        else:
            try:
                last_date = datetime.strptime(
                    last_record[:10],
                    "%Y-%m-%d"
                )

                days_diff = (datetime.now() - last_date).days

                if days_diff <= 7:
                    patient["record_status"] = "active"
                else:
                    patient["record_status"] = "old"

            except:
                patient["record_status"] = "old"

        if visit_day not in grouped_patients:
            grouped_patients[visit_day] = []

        grouped_patients[visit_day].append(patient)

    conn.close()

    return templates.TemplateResponse(
        "doctor_patients.html",
        {
            "request": request,
            "user": user,
            "grouped_patients": grouped_patients,
            "today": today.isoformat()
        }
    )

@app.get("/ui/doctor/patients/{patient_id}/reassign", response_class=HTMLResponse)
def doctor_reassign_patient_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE role = 'doctor' AND is_active = 1
        ORDER BY full_name
    """)
    doctors = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "doctor_reassign_patient.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "doctors": doctors
        }
    )


@app.post("/ui/doctor/patients/{patient_id}/reassign")
def doctor_reassign_patient(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    assigned_doctor_id: int = Form(...)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE id = ? AND role = 'doctor' AND is_active = 1
        """,
        (assigned_doctor_id,),
    )
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid doctor")

    cursor.execute("""
        UPDATE patients
        SET assigned_doctor_id = ?
        WHERE id = ?
    """, (assigned_doctor_id, patient_id))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        INSERT INTO assignment_history (
            patient_id, assigned_doctor_id,
            changed_by_user_id, changed_at
        ) VALUES (?, ?, ?, ?)
    """, (
        patient_id,
        assigned_doctor_id,
        user["id"],
        now_local()
    ))

    cursor.execute("SELECT name, surname FROM patients WHERE id = ?", (patient_id,))
    p = cursor.fetchone()

    cursor.execute("SELECT full_name FROM users WHERE id = ?", (assigned_doctor_id,))
    d = cursor.fetchone()

    cursor.execute(
        """
        INSERT INTO notifications (user_id, patient_id, message, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            assigned_doctor_id,
            patient_id,
            f"Patient {p['name']} {p['surname']} reassigned to you",
            now_local(),
        ),
    )

    log_action(
        cursor,
        action="reassign_patient",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Patient {p['name']} {p['surname']} reassigned to {d['full_name']}"
    )



    conn.commit()
    conn.close()

    return RedirectResponse(
    url="/ui/doctor/patients?reassigned=1",
    status_code=302
)



@app.get("/ui/doctor/patients/{patient_id}", response_class=HTMLResponse)
def doctor_patient_detail(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    # Allow doctor and admin
    if user["role"] not in ("doctor", "admin"):
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    # =========================
    # Load patient
    # =========================
            
    cursor.execute("""
        SELECT *
        FROM patients
        WHERE id = ?
    """, (patient_id,))

    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    # =========================
    # Load medical records
    # =========================
    cursor.execute("""
        SELECT
            medical_records.id,
            medical_records.record_type,
            medical_records.content,
            medical_records.created_at,
            medical_records.updated_at,
            medical_records.created_by_user_id,
            COALESCE(medical_records.record_group, CAST(medical_records.patient_id AS TEXT) || '-' || CAST(medical_records.created_by_user_id AS TEXT) || '-' || medical_records.created_at) AS record_group,
            users.full_name AS author
        FROM medical_records
        JOIN users ON users.id = medical_records.created_by_user_id
        WHERE medical_records.patient_id = ?
        ORDER BY medical_records.created_at DESC, medical_records.id
    """, (patient_id,))

    records = [dict(row) for row in cursor.fetchall()]
    for record in records:
        record["display_type"] = medical_record_label(record["record_type"])
        record["can_edit"] = (
            user["role"] == "doctor"
            and record["created_by_user_id"] == user["id"]
            and is_record_editable(record["created_at"])
        )

    cursor.execute(
        """
        SELECT id, record_group, original_filename, content_type, created_at
        FROM medical_record_attachments
        WHERE patient_id = ?
        ORDER BY created_at, id
        """,
        (patient_id,),
    )
    attachments_by_group = {}
    for row in cursor.fetchall():
        attachment = dict(row)
        attachments_by_group.setdefault(attachment["record_group"], []).append(attachment)

    record_entries = []
    entries_by_group = {}
    for record in records:
        group = record["record_group"]
        if group not in entries_by_group:
            entry = {
                "record_group": group,
                "author": record["author"],
                "created_at": record["created_at"],
                "updated_at": record["updated_at"],
                "can_edit": record["can_edit"],
                "records": [],
                "attachments": attachments_by_group.get(group, []),
            }
            entries_by_group[group] = entry
            record_entries.append(entry)
        entries_by_group[group]["records"].append(record)

    conn.close()

    return templates.TemplateResponse(
        "doctor_patient_detail.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "records": records,
            "record_entries": record_entries,
            "attachments_by_group": attachments_by_group
        }
    )


@app.get("/ui/doctor/patients/{patient_id}/records/add", response_class=HTMLResponse)
def doctor_add_record_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM patients
        WHERE id = ?
    """, (patient_id,))

    patient = cursor.fetchone()
    conn.close()

    if not patient:
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        "doctor_add_record.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient)
        }
    )


@app.post("/ui/doctor/patients/{patient_id}/records/add")
def doctor_add_record_submit(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),

    shikayetler: str = Form(None),
    anamnez: str = Form(None),
    nevrostatus: str = Form(None),
    muayine: str = Form(None),
    diaqnoz: str = Form(None),
    mualice: str = Form(None),
    attachments: list[UploadFile] = File(None)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM patients
        WHERE id = ?
    """, (patient_id,))

    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404)

    now = now_local()
    record_group = uuid.uuid4().hex

    records = [
        ("Şikayətlər", shikayetler),
        ("Anamnez", anamnez),
        ("Nevrostatus", nevrostatus),
        ("Müayinə", muayine),
        ("Diaqnoz", diaqnoz),
        ("Müalicə", mualice)
    ]

    inserted_count = 0

    for record_type, content in records:

        if content and content.strip():

            cursor.execute("""
                INSERT INTO medical_records (
                    patient_id,
                    record_type,
                    content,
                    created_by_user_id,
                    record_group,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                patient_id,
                record_type,
                content,
                user["id"],
                record_group,
                now
            ))
            inserted_count += 1

    has_attachments = any(upload and upload.filename for upload in (attachments or []))
    if inserted_count == 0 and has_attachments:
        cursor.execute("""
            INSERT INTO medical_records (
                patient_id,
                record_type,
                content,
                created_by_user_id,
                record_group,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            patient_id,
            "Əlavələr",
            "Əlavə fayllar",
            user["id"],
            record_group,
            now
        ))
        inserted_count += 1

    attachment_count = 0
    if has_attachments:
        attachment_count = save_uploaded_attachments(attachments, patient_id, record_group, user["id"], cursor)

    log_action(
        cursor,
        action="create_medical_record",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Created medical record group {record_group}. Records: {inserted_count}; attachments: {attachment_count}"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/doctor/patients/{patient_id}?record_added=1",
        status_code=302
    )


@app.get("/ui/doctor/patients/{patient_id}/records/{record_group}/edit", response_class=HTMLResponse)
def doctor_edit_record_page(
    patient_id: int,
    record_group: str,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM patients
        WHERE id = ?
        """,
        (patient_id,),
    )
    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute(
        """
        SELECT *
        FROM medical_records
        WHERE patient_id = ?
        AND record_group = ?
        AND created_by_user_id = ?
        ORDER BY id
        """,
        (patient_id, record_group, user["id"]),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    if not rows:
        conn.close()
        raise HTTPException(status_code=404)

    if not is_record_editable(rows[0]["created_at"]):
        conn.close()
        raise HTTPException(status_code=403, detail="Record can only be edited within 48 hours")

    cursor.execute(
        """
        SELECT id, original_filename, content_type, created_at
        FROM medical_record_attachments
        WHERE patient_id = ? AND record_group = ?
        ORDER BY created_at, id
        """,
        (patient_id, record_group),
    )
    attachments = [dict(row) for row in cursor.fetchall()]
    conn.close()

    values = {medical_record_label(row["record_type"]): row["content"] for row in rows}
    return templates.TemplateResponse(
        "doctor_edit_record.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "record_group": record_group,
            "record_fields": MEDICAL_RECORD_FIELDS,
            "values": values,
            "attachments": attachments,
        }
    )


@app.post("/ui/doctor/patients/{patient_id}/records/{record_group}/edit")
def doctor_edit_record_submit(
    patient_id: int,
    record_group: str,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    shikayetler: str = Form(None),
    anamnez: str = Form(None),
    nevrostatus: str = Form(None),
    muayine: str = Form(None),
    diaqnoz: str = Form(None),
    mualice: str = Form(None),
    attachments: list[UploadFile] = File(None)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM patients
        WHERE id = ?
        """,
        (patient_id,),
    )
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute(
        """
        SELECT *
        FROM medical_records
        WHERE patient_id = ?
        AND record_group = ?
        AND created_by_user_id = ?
        ORDER BY id
        """,
        (patient_id, record_group, user["id"]),
    )
    existing_rows = [dict(row) for row in cursor.fetchall()]
    if not existing_rows:
        conn.close()
        raise HTTPException(status_code=404)

    if not is_record_editable(existing_rows[0]["created_at"]):
        conn.close()
        raise HTTPException(status_code=403, detail="Record can only be edited within 48 hours")

    submitted = {
        "Şikayətlər": shikayetler,
        "Anamnez": anamnez,
        "Nevrostatus": nevrostatus,
        "Müayinə": muayine,
        "Diaqnoz": diaqnoz,
        "Müalicə": mualice,
    }
    existing_by_type = {medical_record_label(row["record_type"]): row for row in existing_rows}
    update_time = now_local()

    for record_type, content in submitted.items():
        content = content or ""
        if record_type in existing_by_type:
            cursor.execute(
                """
                UPDATE medical_records
                SET content = ?, updated_at = ?
                WHERE id = ?
                """,
                (content, update_time, existing_by_type[record_type]["id"]),
            )
        elif content.strip():
            cursor.execute(
                """
                INSERT INTO medical_records (
                    patient_id,
                    record_type,
                    content,
                    created_by_user_id,
                    record_group,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    patient_id,
                    record_type,
                    content,
                    user["id"],
                    record_group,
                    existing_rows[0]["created_at"],
                    update_time,
                ),
            )

    attachment_count = 0
    if any(upload and upload.filename for upload in (attachments or [])):
        attachment_count = save_uploaded_attachments(attachments, patient_id, record_group, user["id"], cursor)

    log_action(
        cursor,
        action="edit_medical_record",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Edited medical record group {record_group}. Attachments added: {attachment_count}"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/doctor/patients/{patient_id}?record_updated=1",
        status_code=302
    )


@app.post("/ui/doctor/patients/{patient_id}/records/{record_group}/delete")
def doctor_delete_record_submit(
    patient_id: int,
    record_group: str,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM medical_records
        WHERE patient_id = ?
        AND record_group = ?
        AND created_by_user_id = ?
        ORDER BY id
        """,
        (patient_id, record_group, user["id"]),
    )
    rows = [dict(row) for row in cursor.fetchall()]
    if not rows:
        conn.close()
        raise HTTPException(status_code=404)

    if not is_record_editable(rows[0]["created_at"]):
        conn.close()
        raise HTTPException(status_code=403, detail="Record can only be deleted within 48 hours")

    cursor.execute(
        """
        SELECT stored_filename
        FROM medical_record_attachments
        WHERE patient_id = ? AND record_group = ?
        """,
        (patient_id, record_group),
    )
    stored_files = [row["stored_filename"] for row in cursor.fetchall()]

    cursor.execute(
        """
        DELETE FROM medical_record_attachments
        WHERE patient_id = ? AND record_group = ?
        """,
        (patient_id, record_group),
    )
    attachment_count = cursor.rowcount

    cursor.execute(
        """
        DELETE FROM medical_records
        WHERE patient_id = ?
        AND record_group = ?
        AND created_by_user_id = ?
        """,
        (patient_id, record_group, user["id"]),
    )
    record_count = cursor.rowcount

    log_action(
        cursor,
        action="delete_medical_record",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Deleted medical record group {record_group}. Records: {record_count}; attachments: {attachment_count}"
    )

    conn.commit()
    conn.close()

    for stored_filename in stored_files:
        try:
            (UPLOAD_DIR / stored_filename).unlink()
        except OSError:
            pass

    return RedirectResponse(
        url=f"/ui/doctor/patients/{patient_id}?record_deleted=1",
        status_code=302
    )


@app.get("/ui/attachments/{attachment_id}")
def view_medical_attachment(
    attachment_id: int,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] not in ("doctor", "admin", "reception"):
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT a.*, p.assigned_doctor_id
        FROM medical_record_attachments a
        JOIN patients p ON p.id = a.patient_id
        WHERE a.id = ?
        """,
        (attachment_id,),
    )
    attachment = cursor.fetchone()
    conn.close()

    if not attachment:
        raise HTTPException(status_code=404)
    response_filename = safe_original_filename(attachment["original_filename"])
    if Path(response_filename).suffix.lower() not in ALLOWED_ATTACHMENT_EXTENSIONS:
        raise HTTPException(status_code=403, detail="Attachment type is not allowed")

    file_path = UPLOAD_DIR / attachment["stored_filename"]
    if not file_path.exists():
        raise HTTPException(status_code=404)

    media_type = attachment["content_type"] or mimetypes.guess_type(attachment["original_filename"])[0] or "application/octet-stream"
    disposition = "inline"

    return FileResponse(
        file_path,
        media_type=media_type,
        filename=response_filename,
        headers={"Content-Disposition": f'{disposition}; filename="{response_filename}"'}
    )


@app.get("/ui/doctor/notifications", response_class=HTMLResponse)
def doctor_notifications(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            notifications.id,
            COALESCE(inferred_by_message.id, notifications.patient_id, inferred_assignment.patient_id) AS patient_id,
            notifications.message,
            notifications.created_at
        FROM notifications
        LEFT JOIN patients inferred_by_message
            ON notifications.message = 'Patient ' || inferred_by_message.name || ' ' || inferred_by_message.surname || ' reassigned to you'
            AND inferred_by_message.assigned_doctor_id = notifications.user_id
        LEFT JOIN assignment_history inferred_assignment
            ON inferred_assignment.assigned_doctor_id = notifications.user_id
            AND inferred_assignment.changed_at = notifications.created_at
            AND notifications.message LIKE 'Patient % reassigned to you'
        WHERE notifications.user_id = ?
        ORDER BY notifications.created_at DESC
    """, (user["id"],))

    notifications = [dict(row) for row in cursor.fetchall()]
    cursor.execute("""
        UPDATE notifications
        SET is_read = 1
        WHERE user_id = ?
    """, (user["id"],))
    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "doctor_notifications.html",
        {
            "request": request,
            "user": user,
            "notifications": notifications
        }
    )

@app.get("/ui/reception/patients", response_class=HTMLResponse)
def reception_patients(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    q: str = "",
    page: int = 1
):

    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    page_size = 25
    page = max(page, 1)
    offset = (page - 1) * page_size
    search = f"%{q.strip()}%"

    conn = get_db_connection()
    cursor = conn.cursor()

    count_sql = """
        SELECT COUNT(*) AS total
        FROM patients
        WHERE is_active = 1
        AND (
            name LIKE ?
            OR surname LIKE ?
            OR father_name LIKE ?
            OR phone LIKE ?
        )
    """
    cursor.execute(count_sql, (search, search, search, search))
    total_patients = cursor.fetchone()["total"]
    total_pages = max((total_patients + page_size - 1) // page_size, 1)
    if page > total_pages:
        page = total_pages
        offset = (page - 1) * page_size

    cursor.execute("""
        SELECT
            patients.id,
            patients.name,
            patients.surname,
            patients.father_name,
            patients.phone,
            patients.assigned_examination,
            users.full_name AS doctor_name
        FROM patients
        JOIN users ON users.id = patients.assigned_doctor_id
        WHERE patients.is_active = 1
        AND (
            patients.name LIKE ?
            OR patients.surname LIKE ?
            OR patients.father_name LIKE ?
            OR patients.phone LIKE ?
        )
        ORDER BY patients.id DESC
        LIMIT ? OFFSET ?
    """, (search, search, search, search, page_size, offset))


    patients = [dict(row) for row in cursor.fetchall()][:page_size]
    conn.close()

    return templates.TemplateResponse(
        "reception_patients.html",
        {
            "request": request,
            "user": user,
            "patients": patients,
            "q": q,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "total_patients": total_patients,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            "prev_page": page - 1,
            "next_page": page + 1
        }
    )

@app.get("/ui/reception/patients/{patient_id}/payments", response_class=HTMLResponse)
def reception_payment_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        SELECT id, payment_type, amount, created_at
        FROM payments
        WHERE patient_id = ?
        ORDER BY created_at DESC
    """, (patient_id,))

    payments = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "reception_payment.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "payments": payments
        }
    )

@app.post("/ui/reception/patients/{patient_id}/payments")
def reception_payment_submit(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    payment_type: str = Form(...),
    amount: float = Form(...)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, surname FROM patients WHERE id = ? AND is_active = 1",
        (patient_id,),
    )
    p = cursor.fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        INSERT INTO payments (
            patient_id, payment_type, amount,
            received_by_user_id, created_at
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        patient_id,
        payment_type,
        amount,
        user["id"],
        now_local()
    ))

    message = f"Payment received for {p['name']} {p['surname']}: {amount} AZN ({payment_type})"

    cursor.execute("""
        INSERT INTO notifications (user_id, message, created_at)
        VALUES (?, ?, ?)
    """, (
        user["id"],
        message,
        now_local()
    ))

    log_action(
        cursor,
        action="record_payment",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Payment {amount} AZN for {payment_type} — {p['name']} {p['surname']}"
    )


    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/reception/patients/{patient_id}/payments?success=1&amount={amount}&type={payment_type}",
        status_code=302
)

@app.post("/ui/reception/payments/{payment_id}/delete")
def reception_delete_payment(
    payment_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT patient_id, amount, payment_type
        FROM payments
        WHERE id = ?
    """, (payment_id,))

    payment = cursor.fetchone()

    if not payment:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        DELETE FROM payments
        WHERE id = ?
    """, (payment_id,))

    log_action(
        cursor,
        action="delete_payment",
        entity_type="payment",
        entity_id=payment_id,
        user_id=user["id"],
        details=f"Deleted payment: {payment['amount']} AZN ({payment['payment_type']})"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/reception/patients/{payment['patient_id']}/payments?payment_deleted=1",
        status_code=302
    )


@app.get("/ui/reception/patients/{patient_id}/edit", response_class=HTMLResponse)
def reception_edit_patient_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM patients WHERE id = ?",
        (patient_id,)
    )
    patient = cursor.fetchone()
    conn.close()

    if not patient:
        raise HTTPException(status_code=404)

    return templates.TemplateResponse(
        "reception_edit_patient.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient)
        }
    )
@app.post("/ui/reception/patients/{patient_id}/edit")
def reception_edit_patient_submit(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    name: str = Form(...),
    surname: str = Form(...),
    father_name: str = Form(...),
    phone: str = Form(...),
    region: str = Form(...),
    date_of_birth: str = Form(...)
):
    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE patients
        SET
            name = ?,
            surname = ?,
            father_name = ?,
            phone = ?,
            region = ?,
            date_of_birth = ?
        WHERE id = ?
    """, (
        name,
        surname,
        father_name,
        phone,
        region,
        date_of_birth,
        patient_id
    ))

    log_action(
    cursor,
    action="edit_patient",
    entity_type="patient",
    entity_id=patient_id,
    user_id=user["id"],
    details="Administrative data updated"
)


    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/ui/reception/patients?updated=1",
        status_code=302
    )


@app.post("/ui/reception/patients/{patient_id}/delete")
def reception_delete_patient(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
):
    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT name, surname FROM patients WHERE id = ?",
        (patient_id,)
    )
    patient = cursor.fetchone()

    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        UPDATE patients
        SET is_active = 0
        WHERE id = ?
    """, (patient_id,))

    cursor.execute("""
        DELETE FROM payments
        WHERE patient_id = ?
    """, (patient_id,))

    log_action(
        cursor,
        action="delete_patient",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Patient deleted: {patient['name']} {patient['surname']}"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/ui/reception/patients?deleted=1",
        status_code=302
    )

@app.get("/ui/reception/patients/{patient_id}/assign", response_class=HTMLResponse)
def reception_reassign_patient_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE role = 'doctor' AND is_active = 1
        ORDER BY full_name
    """)
    doctors = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "reception_reassign_patient.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "doctors": doctors
        }
    )

@app.post("/ui/reception/patients/{patient_id}/assign")
def reception_reassign_patient_submit(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    assigned_doctor_id: int = Form(...),
    assigned_examination: str = Form(None)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE id = ? AND role = 'doctor' AND is_active = 1
        """,
        (assigned_doctor_id,),
    )
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid doctor")

    cursor.execute("""
        UPDATE patients
        SET assigned_doctor_id = ?, assigned_examination = ?
        WHERE id = ?
    """, (
        assigned_doctor_id,
        assigned_examination,
        patient_id
    ))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        INSERT INTO assignment_history (
            patient_id,
            assigned_doctor_id,
            assigned_examination,
            changed_by_user_id,
            changed_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        patient_id,
        assigned_doctor_id,
        assigned_examination,
        user["id"],
        now_local()
    ))

    cursor.execute(
        "SELECT name, surname FROM patients WHERE id = ?",
        (patient_id,)
    )
    p = cursor.fetchone()

    message = f"Patient {p['name']} {p['surname']} reassigned to you"

    cursor.execute("""
        INSERT INTO notifications (user_id, patient_id, message, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        assigned_doctor_id,
        patient_id,
        message,
        now_local()
    ))


    # notify admin
    cursor.execute("""
        INSERT INTO notifications (user_id, patient_id, message, created_at)
        SELECT id, ?, ?, ?
        FROM users
        WHERE role = 'admin'
    """, (
        patient_id,
        f"Reception reassigned patient ID {patient_id} to doctor ID {assigned_doctor_id}",
        now_local()
    ))

    cursor.execute("SELECT name, surname FROM patients WHERE id = ?", (patient_id,))
    p = cursor.fetchone()

    cursor.execute("SELECT full_name FROM users WHERE id = ?", (assigned_doctor_id,))
    d = cursor.fetchone()

    log_action(
        cursor,
        action="reassign_patient",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Patient {p['name']} {p['surname']} reassigned to {d['full_name']}"
    )



    conn.commit()
    conn.close()

    return RedirectResponse(
        url="/ui/reception/patients?reassigned=1",
        status_code=302
    )

@app.get("/ui/reception/patients/{patient_id}/profile", response_class=HTMLResponse)
def reception_patient_profile(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("""
        SELECT payment_type, amount, created_at
        FROM payments
        WHERE patient_id = ?
        ORDER BY created_at DESC
    """, (patient_id,))
    payments = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(
        "reception_patient_profile.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "payments": payments
        }
    )

@app.post("/ui/reception/patients/{patient_id}/profile")
def reception_patient_profile_submit(
    patient_id: int,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    notes: str = Form(None),
    status: str = Form(None)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE patients SET notes = ?, status = ? WHERE id = ?",
        (notes, status, patient_id)
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404)

    cursor.execute("SELECT name, surname FROM patients WHERE id = ?", (patient_id,))
    p = cursor.fetchone()

    log_action(
        cursor,
        action="update_patient_profile",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Profile updated for {p['name']} {p['surname']} (status: {status})"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/reception/patients/{patient_id}/profile?updated=1",
        status_code=302
    )




@app.get("/ui/reception/patients/create", response_class=HTMLResponse)
def reception_create_patient_page(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE role = 'doctor' AND is_active = 1
        ORDER BY full_name
    """)
    doctors = [dict(row) for row in cursor.fetchall()]
    conn.close()

    today_value = datetime.now()

    return templates.TemplateResponse(
        "reception_create_patient.html",
        {
            "request": request,
            "user": user,
            "doctors": doctors,
            "today": today_value.strftime("%Y-%m-%d"),
            "today_day": today_value.strftime("%d"),
            "today_month": today_value.strftime("%m"),
            "today_year": today_value.year,
            "current_year": today_value.year
        }
    )

@app.post("/ui/reception/patients/create")
def reception_create_patient_submit(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    name: str = Form(...),
    surname: str = Form(...),
    father_name: str = Form(...),
    date_of_birth: str = Form(...),
    gender: str = Form(...),
    region: str = Form(...),
    phone: str = Form(...),
    assigned_doctor_id: int = Form(...),
    assigned_examination: str = Form(None),
    status: str = Form(None),
    first_registration_date: str = Form(...),
    source: str = Form(None),
    source_details: str = Form(None),
):
    if user["role"] not in ["reception", "doctor"]:
        raise HTTPException(status_code=403)

    # Normalize source (use details only if "Digər")
    final_source = source
    if source == "Digər" and source_details:
        final_source = source_details

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE id = ? AND role = 'doctor' AND is_active = 1
        """,
        (assigned_doctor_id,),
    )
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid doctor")

    cursor.execute("""
        INSERT INTO patients (
            name, surname, father_name, date_of_birth,
            gender, region, phone,
            assigned_doctor_id, assigned_examination,
            status, first_registration_date, source, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        name, surname, father_name, date_of_birth,
        gender, region, phone,
        assigned_doctor_id, assigned_examination,
        status, first_registration_date, final_source,
        now_local()
    ))

    patient_id = cursor.lastrowid

    cursor.execute("""
        INSERT INTO assignment_history (
            patient_id, assigned_doctor_id, assigned_examination,
            changed_by_user_id, changed_at
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        patient_id,
        assigned_doctor_id,
        assigned_examination,
        user["id"],
        now_local()
    ))

    log_action(
        cursor,
        action="create_patient",
        entity_type="patient",
        entity_id=patient_id,
        user_id=user["id"],
        details=f"Patient created: {name} {surname}"
    )

    conn.commit()
    conn.close()

    return RedirectResponse(
    url="/ui/reception/patients?created=1",
    status_code=302
    )


@app.get("/ui/reception/costs", response_class=HTMLResponse)
def reception_costs_page(request: Request, user=Depends(get_current_user_from_cookie)):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    categories = [
        "İçməli su",
        "Yeyinti malları (çay, kofe, konfet və s.)",
        "Tibbi ləvazimatlar (əlcək, spirt və s.)",
        "Kartric yenilənməsi",
        "Qaz ödənişi",
        "İşiq ödənişi",
        "Su ödənişi",
        "San Epidem Stansiya",
        "Polis",
        "Tullantı ödənişi",
        "Digər ödənişlər",
    ]

    return templates.TemplateResponse(
        "reception_costs.html",
        {"request": request, "user": user, "categories": categories}
    )

@app.post("/ui/reception/costs")
async def reception_costs_submit(
    request: Request,
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
    category_index: int = Form(...)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    form = await request.form()

    categories = [
        "Д°Г§mЙ™li su",
        "Yeyinti mallarД± (Г§ay, kofe, konfet vЙ™ s.)",
        "Tibbi lЙ™vazimatlar (Й™lcЙ™k, spirt vЙ™ s.)",
        "Kartric yenilЙ™nmЙ™si",
        "Qaz Г¶dЙ™niЕџi",
        "Д°Еџiq Г¶dЙ™niЕџi",
        "Su Г¶dЙ™niЕџi",
        "San Epidem Stansiya",
        "Polis",
        "TullantД± Г¶dЙ™niЕџi",
        "DigЙ™r Г¶dЙ™niЕџlЙ™r",
    ]
    if category_index < 1 or category_index > len(categories):
        raise HTTPException(status_code=400, detail="Invalid category")

    category = categories[category_index - 1]
    amount = form.get(f"amount_{category_index}")
    details = form.get(f"details_{category_index}")
    if not amount:
        raise HTTPException(status_code=400, detail="Amount is required")
    try:
        amount_value = float(amount)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid amount")
    if amount_value <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO costs (category, details, amount, created_by_user_id, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        category,
        details,
        amount_value,
        user["id"],
        now_local()
    ))

    log_action(
        cursor,
        action="add_cost",
        entity_type="cost",
        entity_id=cursor.lastrowid,
        user_id=user["id"],
        details=f"Cost added: {category} — {amount} AZN"
    )

    conn.commit()
    conn.close()

    return RedirectResponse("/ui/reception/costs?success=1", status_code=302)

@app.get("/profile")
def profile_page(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user
        }
    )

@app.post("/profile")
def profile_update(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user=Depends(get_current_user_from_cookie),
    csrf=Depends(require_csrf),
):
    if new_password != confirm_password:
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "user": user,
                "error": "Yeni şifrələr uyğun gəlmir"
            }
        )
    if len(new_password) < 8:
        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "user": user,
                "error": "Yeni şifrə ən azı 8 simvol olmalıdır"
            }
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user["id"],)
    )

    db_user = cursor.fetchone()

    if not verify_password(current_password, db_user["password_hash"]):
        conn.close()

        return templates.TemplateResponse(
            "profile.html",
            {
                "request": request,
                "user": user,
                "error": "Cari şifrə yanlışdır"
            }
        )

    new_hash = hash_password(new_password)

    cursor.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (new_hash, user["id"]))

    log_action(
        cursor,
        action="change_own_password",
        entity_type="user",
        entity_id=user["id"],
        user_id=user["id"],
        details="User changed own password"
    )

    conn.commit()
    conn.close()

    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": user,
            "success": "Şifrə uğurla dəyişdirildi"
        }
    )


