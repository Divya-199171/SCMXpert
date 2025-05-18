# app/routers/user.py

from fastapi import APIRouter, Request, Form, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from datetime import datetime, timedelta, timezone
import requests

from core.database import users_collection, logins_collection
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    get_current_user, get_required_current_user, get_current_admin_user
)
from core.config import RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=RedirectResponse)
def root():
    return RedirectResponse(url="/login")


@router.get("/login", response_class=HTMLResponse)
def get_login(request: Request, error: str = None, message: str = None):
    token = request.cookies.get("access_token")
    if token:
        from jose import jwt, JWTError
        from core.config import SECRET_KEY, ALGORITHM
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            role = payload.get("role")
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if role == "admin" else "/dashboard")
        except JWTError:
            pass
    response = templates.TemplateResponse("login.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "error": error,
        "message": message
    })
    if error or message:
        response.delete_cookie("access_token")
    return response


@router.post("/login", response_class=RedirectResponse)
async def post_login(
    request: Request,
    username: EmailStr = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response")
):
    # reCAPTCHA validation
    recaptcha_verify = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_SECRET_KEY, "response": g_recaptcha_response}
    ).json()

    if not recaptcha_verify.get("success"):
        return RedirectResponse(url="/login?error=reCAPTCHA+failed", status_code=303)

    user = users_collection.find_one({"email": username})
    if user and verify_password(password, user["password_hash"]):
        token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user.get("role", "user")},
            expires_delta=token_expires
        )

        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.now(timezone.utc),
            "status": "success"
        })

        redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
        response = RedirectResponse(url=f"{redirect_url}?message=Successfully+logged+in", status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            samesite="lax"
        )
        return response

    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.now(timezone.utc),
        "status": "failed"
    })
    return RedirectResponse(url="/login?error=Invalid+credentials", status_code=303)



@router.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request, error: str = None):
    return templates.TemplateResponse("signup.html", {"request": request, "error": error})


@router.post("/signup", response_class=RedirectResponse)
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    role: str = Form(...)
):
    import re

    # Validate fullname contains only letters and spaces
    if not re.fullmatch(r"[A-Za-z ]+", fullname):
        return RedirectResponse(url="/signup?error=Full+Name+must+only+contain+letters+and+spaces.", status_code=303)

    # Password match check
    if password != confirm_password:
        return RedirectResponse(url="/signup?error=Passwords+do+not+match.", status_code=303)

    # Email already exists
    if users_collection.find_one({"email": email}):
        return RedirectResponse(url="/signup?error=Email+already+registered.", status_code=303)

    # Default role validation
    if role not in ["user", "admin"]:
        role = "user"

    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": get_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc)
    })

    return RedirectResponse(url="/login?message=Account+created+successfully,+please+login.", status_code=303)



@router.get("/logout", response_class=RedirectResponse)
def logout(request: Request):
    response = RedirectResponse(url="/login?message=Logged+out+successfully", status_code=303)
    response.delete_cookie("access_token")
    return response


@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_required_current_user)):
    if current_user["role"] == "admin":
        return RedirectResponse(url="/admin-dashboard")
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "name": current_user["name"],
        "message": request.query_params.get("message")
    })

@router.get("/user-profile", response_class=HTMLResponse)
def get_user_profile(request: Request, current_user: dict = Depends(get_required_current_user)):
    return templates.TemplateResponse("user-profile.html", {
        "request": request,
        "user": current_user
    })


@router.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "name": current_user["name"]
    })
