from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from auth.security import get_or_create_csrf_token, require_admin_ui, require_csrf
from services.admin_user_service import create_user, reset_user_password

router = APIRouter()
templates = Jinja2Templates(directory="templates")
templates.env.globals["csrf_token"] = get_or_create_csrf_token


@router.get("/ui/admin/users/create", response_class=HTMLResponse)
def admin_create_user_page(
    request: Request,
    user=Depends(require_admin_ui),
):
    return templates.TemplateResponse(
        "admin_create_user.html",
        {"request": request, "user": user},
    )


@router.post("/admin/users/create", response_class=HTMLResponse)
def admin_create_user(
    request: Request,
    username: str = Form(...),
    full_name: str = Form(...),
    role: str = Form(...),
    password: str | None = Form(None),
    user=Depends(require_admin_ui),
    csrf=Depends(require_csrf),
):
    try:
        result = create_user(
            admin_user_id=user["id"],
            username=username,
            full_name=full_name,
            role=role,
            password=password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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


@router.post("/admin/users/reset-password")
def admin_reset_password(
    user_id: int = Form(...),
    user=Depends(require_admin_ui),
    csrf=Depends(require_csrf),
):
    try:
        return reset_user_password(
            admin_user_id=user["id"],
            target_user_id=user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
