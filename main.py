from fastapi import (
    FastAPI,
    Request,
    Form,
    HTTPException,
    Depends,
    status,
)

from fastapi.staticfiles import StaticFiles
from datetime import datetime

def now_local():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

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
    verify_password,
    hash_password
)


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(admin_users_router)

templates = Jinja2Templates(directory="templates")

# ======================================================
# GLOBAL UI AUTH HANDLER
# ======================================================

@app.exception_handler(HTTPException)
def ui_http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse(url="/login")
    raise exc

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
    try:
        result = authenticate_user_and_return_token(username, password)
    except HTTPException:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
        )

    role = result["role"]

    if role == "admin":
        redirect_url = "/admin"
    elif role == "reception":
        redirect_url = "/reception"
    elif role == "doctor":
        redirect_url = "/doctor"
    else:
        redirect_url = "/login"

    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie(
        key="session_token",
        value=result["token"],
        httponly=True,
    )
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
    username: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    password: str = Form(None)
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

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
    user=Depends(get_current_user_from_cookie)
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
    q: str = ""
):
    if user["role"] != "admin":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, name, surname, phone
        FROM patients
        WHERE name LIKE ? OR surname LIKE ?
        ORDER BY id DESC
    """, (f"%{q}%", f"%{q}%"))

    patients = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "admin_patients.html",
        {
            "request": request,
            "user": user,
            "patients": patients
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

    cursor.execute("""
        SELECT
            id,
            name,
            surname,
            date_of_birth,
            phone,
            assigned_examination
        FROM patients
        WHERE assigned_doctor_id = ?
        AND (name LIKE ? OR surname LIKE ?)
        ORDER BY id DESC
    """, (user["id"], f"%{q}%", f"%{q}%"))


    patients = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "doctor_patients.html",
        {
            "request": request,
            "user": user,
            "patients": patients
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

    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE role = 'doctor'
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
    assigned_doctor_id: int = Form(...)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE patients
        SET assigned_doctor_id = ?
        WHERE id = ?
    """, (assigned_doctor_id, patient_id))

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
    url="/ui/doctor/patients",
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
    if user["role"] == "doctor":
        cursor.execute("""
            SELECT *
            FROM patients
            WHERE id = ? AND assigned_doctor_id = ?
        """, (patient_id, user["id"]))
    else:  # admin
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
            medical_records.record_type,
            medical_records.content,
            medical_records.created_at,
            users.full_name AS author
        FROM medical_records
        JOIN users ON users.id = medical_records.created_by_user_id
        WHERE medical_records.patient_id = ?
        ORDER BY medical_records.created_at DESC
    """, (patient_id,))

    records = [dict(row) for row in cursor.fetchall()]
    conn.close()

    print("DEBUG patient keys:", dict(patient).keys())
    print("DEBUG patient source:", dict(patient).get("source"))
    return templates.TemplateResponse(
        "doctor_patient_detail.html",
        {
            "request": request,
            "user": user,
            "patient": dict(patient),
            "records": records
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
        WHERE id = ? AND assigned_doctor_id = ?
    """, (patient_id, user["id"]))

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
    note: str = Form(None),
    diagnosis: str = Form(None),
    prescription: str = Form(None)
):
    if user["role"] != "doctor":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM patients
        WHERE id = ? AND assigned_doctor_id = ?
    """, (patient_id, user["id"]))

    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404)

    now = now_local()

    if note:
        cursor.execute("""
            INSERT INTO medical_records (
                patient_id, record_type, content, created_by_user_id, created_at
            ) VALUES (?, 'note', ?, ?, ?)
        """, (patient_id, note, user["id"], now))

    if diagnosis:
        cursor.execute("""
            INSERT INTO medical_records (
                patient_id, record_type, content, created_by_user_id, created_at
            ) VALUES (?, 'diagnosis', ?, ?, ?)
        """, (patient_id, diagnosis, user["id"], now))

    if prescription:
        cursor.execute("""
            INSERT INTO medical_records (
                patient_id, record_type, content, created_by_user_id, created_at
            ) VALUES (?, 'prescription', ?, ?, ?)
        """, (patient_id, prescription, user["id"], now))

    conn.commit()
    conn.close()

    return RedirectResponse(
        url=f"/ui/doctor/patients/{patient_id}",
        status_code=302
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
        SELECT message, created_at
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user["id"],))

    notifications = [dict(row) for row in cursor.fetchall()]
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
    q: str = ""
):

    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

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
        WHERE patients.name LIKE ? OR patients.surname LIKE ?
        ORDER BY patients.id DESC
    """, (f"%{q}%", f"%{q}%"))


    patients = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "reception_patients.html",
        {
            "request": request,
            "user": user,
            "patients": patients
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
        SELECT payment_type, amount, created_at
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
    payment_type: str = Form(...),
    amount: float = Form(...)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

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

    cursor.execute(
        "SELECT name, surname FROM patients WHERE id = ?",
        (patient_id,)
    )
    p = cursor.fetchone()

    message = f"Payment received for {p['name']} {p['surname']}: {amount} AZN ({payment_type})"

    cursor.execute("""
        INSERT INTO notifications (user_id, message, created_at)
        VALUES (?, ?, ?)
    """, (
        user["id"],
        message,
        now_local()
    ))


    cursor.execute("SELECT name, surname FROM patients WHERE id = ?", (patient_id,))
    p = cursor.fetchone()

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




@app.get("/ui/reception/patients/{patient_id}/edit", response_class=HTMLResponse)
def reception_edit_patient_page(
    patient_id: int,
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
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
    name: str = Form(...),
    surname: str = Form(...),
    father_name: str = Form(...),
    phone: str = Form(...),
    region: str = Form(...)
):
    if user["role"] != "reception":
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
            region = ?
        WHERE id = ?
    """, (
        name,
        surname,
        father_name,
        phone,
        region,
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
        url="/ui/reception/patients",
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
        WHERE role = 'doctor'
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
    assigned_doctor_id: int = Form(...),
    assigned_examination: str = Form(None)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE patients
        SET assigned_doctor_id = ?, assigned_examination = ?
        WHERE id = ?
    """, (
        assigned_doctor_id,
        assigned_examination,
        patient_id
    ))

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
        INSERT INTO notifications (user_id, message, created_at)
        VALUES (?, ?, ?)
    """, (
        assigned_doctor_id,
        message,
        now_local()
    ))


    # notify admin
    cursor.execute("""
        INSERT INTO notifications (user_id, message, created_at)
        SELECT id, ?, ?
        FROM users
        WHERE role = 'admin'
    """, (
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
        url="/ui/reception/patients",
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
        url=f"/ui/reception/patients/{patient_id}/profile",
        status_code=302
    )




@app.get("/ui/reception/patients/create", response_class=HTMLResponse)
def reception_create_patient_page(
    request: Request,
    user=Depends(get_current_user_from_cookie)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, full_name
        FROM users
        WHERE role = 'doctor'
        ORDER BY full_name
    """)
    doctors = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(
        "reception_create_patient.html",
        {
            "request": request,
            "user": user,
            "doctors": doctors
        }
    )

@app.post("/ui/reception/patients/create")
def reception_create_patient_submit(
    request: Request,
    user=Depends(get_current_user_from_cookie),
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
    source: str = Form(None),
    source_details: str = Form(None),
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    # Normalize source (use details only if "Digər")
    final_source = source
    if source == "Digər" and source_details:
        final_source = source_details

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO patients (
            name, surname, father_name, date_of_birth,
            gender, region, phone,
            assigned_doctor_id, assigned_examination,
            status, source, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        name, surname, father_name, date_of_birth,
        gender, region, phone,
        assigned_doctor_id, assigned_examination,
        status, final_source,
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
    category: str = Form(...)
):
    if user["role"] != "reception":
        raise HTTPException(status_code=403)

    form = await request.form()

    # Find amount/details by submitted category index
    amount = None
    details = None

    for key, value in form.items():
        if key.startswith("amount_") and value:
            amount = value
        if key.startswith("details_") and value:
            details = value

    if not amount:
        raise HTTPException(status_code=400, detail="Amount is required")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO costs (category, details, amount, created_by_user_id, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (
        category,
        details,
        float(amount),
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




