from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from auth.security import require_admin_ui
from services.admin_user_service import create_user, reset_user_password

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# =========================
# UI PAGE
# =========================

@router.get("/ui/admin/users/create", response_class=HTMLResponse)
def admin_create_user_page(
    request: Request,
    user=Depends(require_admin_ui),
):
    return templates.TemplateResponse(
        "admin_create_user.html",
        {"request": request, "user": user},
    )

# =========================
# UI ACTION
# =========================

@router.post("/admin/users/create", response_class=HTMLResponse)
def admin_create_user(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(...),   # ← ADD THIS
    role: str = Form(...),
    password: str | None = Form(None),
    user=Depends(require_admin_ui),
):

    result = create_user(
    admin_user_id=user["id"],
    username=username,
    full_name=full_name,   # ← ADD THIS
    role=role,
    password=password,
)


    return templates.TemplateResponse(
        "admin_create_user.html",
        {
            "request": request,
            "user": user,
            "success": True,
            "created_username": result["username"],
            "created_password": result["password"],
        },
    )

# =========================
# RESET PASSWORD
# =========================

@router.post("/admin/users/reset-password")
def admin_reset_password(
    user_id: int = Form(...),
    user=Depends(require_admin_ui),
):
    return reset_user_password(
        admin_user_id=user["id"],
        target_user_id=user_id,
    )
