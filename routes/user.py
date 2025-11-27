# app/routers/user.py

import os
import logging
import secrets
import hashlib
import uuid
import urllib.parse
import smtplib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from email.message import EmailMessage

# Third-party imports
import requests  # For ReCaptcha
import httpx     # For Google SSO
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr
from jose import JWTError

# Local imports
from core.database import users_collection, logins_collection, shipments_collection, db
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    decode_token, get_required_current_user,
    get_current_admin_user
)
# ... existing imports ...
from core.limiter import limiter
from core.config import (
    RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Load Environment
load_dotenv()
logger = logging.getLogger(__name__)

# Router Setup
router = APIRouter(tags=["User Authentication and Web"])
templates = Jinja2Templates(directory="templates")

# --- Configuration & Constants ---

COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "False").lower() == "true"
COOKIE_SAMESITE_POLICY = "none" if COOKIE_SECURE_ENABLED else "lax"

# Google SSO Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
GOOGLE_OAUTH_SCOPES = os.getenv("GOOGLE_OAUTH_SCOPES", "openid email profile")
GOOGLE_OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"

# OTP / Email Config
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
OTP_HASH_SECRET = os.getenv("OTP_HASH_SECRET", os.getenv("SECRET_KEY", "change_this_secret"))
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0") or 0)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

# OAuth Scheme for API
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

# MongoDB Collection for Resets (Created dynamically if not in database.py)
password_resets_collection = db["password_resets"]

# --- Helper Functions ---

def verify_recaptcha(token: str) -> bool:
    if not RECAPTCHA_SECRET_KEY:
        logger.warning("RECAPTCHA_SECRET_KEY is not set. Skipping verification.")
        return True
    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": token},
            timeout=5
        )
        response.raise_for_status()
        return response.json().get("success", False)
    except requests.exceptions.RequestException as e:
        logger.error(f"reCAPTCHA verification failed: {str(e)}")
        return False

def generate_numeric_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp_for_storage(otp: str) -> str:
    h = hashlib.sha256()
    h.update((OTP_HASH_SECRET + otp).encode("utf-8"))
    return h.hexdigest()

def send_otp_email(to_email: str, otp: str) -> bool:
    reset_text = f"Your SCMXpertLite OTP is: {otp}\nIt expires in {OTP_EXPIRE_MINUTES} minutes.\nIf you did not request this, ignore."
    if not SMTP_HOST or not SMTP_PORT or not SMTP_USER or not SMTP_PASS:
        logger.warning("SMTP not configured - printing OTP to logs for dev/testing.")
        logger.info(f"OTP for {to_email}: {otp}")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = "SCMXpertLite — Password reset OTP"
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(reset_text)

        if SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        logger.info(f"Sent OTP to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Error sending OTP email to {to_email}: {e}")
        return False

# --- Google SSO Helpers ---

def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": GOOGLE_OAUTH_SCOPES,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "state": state,
        "access_type": "offline",
        "prompt": "select_account"
    }
    return f"{GOOGLE_OAUTH_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"

async def exchange_code_for_tokens(code: str, redirect_uri: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response.raise_for_status()
        return response.json()

async def get_google_userinfo(access_token: str):
    userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient() as client:
        response = await client.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()

# --- Routes: Standard Auth ---

@router.get("/", response_class=RedirectResponse)
def root(request: Request):
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except Exception:
            response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token")
            return response
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/login", response_class=HTMLResponse)
def get_login(request: Request, error: str = None, message: str = None, email: str = None):
    # Check if already logged in
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except JWTError:
            pass 

    return templates.TemplateResponse("login.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "error": error,
        "message": message,
        "email_value": email
    })

@router.post("/login", response_class=RedirectResponse)
@limiter.limit("5/minute")
async def post_login(
    request: Request,
    username: EmailStr = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
):
    if not verify_recaptcha(g_recaptcha_response):
        return RedirectResponse(url="/login?error=reCAPTCHA+failed", status_code=status.HTTP_303_SEE_OTHER)

    user = users_collection.find_one({"email": username})
    if not user or not verify_password(password, user["password_hash"]):
        logins_collection.insert_one({
            "email": username,
            "login_time": datetime.now(timezone.utc),
            "status": "failed",
            "ip_address": request.client.host if request.client else "unknown"
        })
        return RedirectResponse(url=f"/login?error=Invalid+credentials&email={username}", status_code=status.HTTP_303_SEE_OTHER)

    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
        expires_delta=token_expires
    )

    logins_collection.insert_one({
        "email": username,
        "login_time": datetime.now(timezone.utc),
        "status": "success",
        "ip_address": request.client.host if request.client else "unknown"
    })

    redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
    response = RedirectResponse(url=f"{redirect_url}?message=Successfully+logged+in", status_code=status.HTTP_303_SEE_OTHER)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE_ENABLED,
        max_age=int(token_expires.total_seconds()),
        samesite=COOKIE_SAMESITE_POLICY,
        path="/"
    )
    # Utility cookies for JS (Not HttpOnly)
    for key, val in [("user_name", user.get("name", "")), ("user_email", user["email"]), ("user_role", user.get("role", "user"))]:
        response.set_cookie(key=key, value=val, secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
    
    return response

@router.get("/logout", response_class=RedirectResponse)
def logout(request: Request):
    response = RedirectResponse(url="/login?message=Logged+out+successfully", status_code=status.HTTP_303_SEE_OTHER)
    for cookie in ["access_token", "user_email", "user_role", "user_name"]:
        response.delete_cookie(cookie, path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    return response

# --- Routes: Signup ---

@router.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request, error: str = None):
    # Check if already logged in
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except Exception:
            pass
    return templates.TemplateResponse("signup.html", {
        "request": request,
        "error": error,
        "site_key": RECAPTCHA_SITE_KEY 
    })

@router.post("/signup", response_class=RedirectResponse)
def post_signup(
    request: Request,
    fullname: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    if password != confirm_password:
        return RedirectResponse(url="/signup?error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    if users_collection.find_one({"email": email}):
        return RedirectResponse(url="/signup?error=Email+already+registered", status_code=status.HTTP_303_SEE_OTHER)

    # Basic role logic
    role = "admin" if email.endswith("@admin.com") else "user"
    
    users_collection.insert_one({
        "name": fullname,
        "email": email,
        "password_hash": get_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
        "email_verified": False 
    })

    return RedirectResponse(url="/login?message=Account+created+successfully.+Please+log+in.", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: Google SSO ---

@router.get("/auth/google/login", name="google_login", response_class=RedirectResponse)
def google_login(request: Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("[GOOGLE SSO] Missing client id/secret in env")
        return RedirectResponse(url="/login?error=Google+SSO+not+configured", status_code=status.HTTP_303_SEE_OTHER)

    state = secrets.token_urlsafe(32)
    auth_url = build_google_auth_url(state)

    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        "oauth_state",
        state,
        max_age=300,
        httponly=True,
        secure=COOKIE_SECURE_ENABLED,
        samesite=COOKIE_SAMESITE_POLICY,
        path="/"
    )
    return response

@router.get("/auth/google/callback", response_class=RedirectResponse)
async def google_callback(request: Request, code: str = None, state: str = None, error: str = None):
    if error:
        return RedirectResponse(url="/login?error=Google+login+failed", status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        return RedirectResponse(url="/login?error=Missing+code+or+state", status_code=status.HTTP_303_SEE_OTHER)

    cookie_state = request.cookies.get("oauth_state")
    if not cookie_state or cookie_state != state:
        resp = RedirectResponse(url="/login?error=Invalid+OAuth+state", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp

    try:
        # 1. Exchange Code
        token_resp = await exchange_code_for_tokens(code, GOOGLE_REDIRECT_URI)
        access_token_google = token_resp.get("access_token")
        
        if not access_token_google:
            resp = RedirectResponse(url="/login?error=Google+token+failed", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # 2. Get User Info
        userinfo = await get_google_userinfo(access_token_google)
        email = userinfo.get("email")
        name = userinfo.get("name") or userinfo.get("given_name") or "User"

        if not email:
            resp = RedirectResponse(url="/login?error=Google+email+missing", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # 3. DB Logic
        user = users_collection.find_one({"email": email})
        if not user:
            users_collection.insert_one({
                "name": name,
                "email": email,
                "password_hash": "", # SSO User
                "role": "user",
                "created_at": datetime.now(timezone.utc),
                "email_verified": True,
                "sso_provider": "google",
                "sso_sub": userinfo.get("sub")
            })
            user = users_collection.find_one({"email": email})

        # 4. Login Logging
        logins_collection.insert_one({
            "email": email,
            "login_time": datetime.now(timezone.utc),
            "status": "success_google_sso",
            "ip_address": request.client.host if request.client else "unknown"
        })

        # 5. Create Token & Response
        token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
            expires_delta=token_expires
        )

        redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
        resp = RedirectResponse(url=f"{redirect_url}?message=Login+successful", status_code=status.HTTP_303_SEE_OTHER)

        resp.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=COOKIE_SECURE_ENABLED,
            max_age=int(token_expires.total_seconds()),
            samesite=COOKIE_SAMESITE_POLICY,
            path="/"
        )
        for key, val in [("user_name", user.get("name", "")), ("user_email", user["email"]), ("user_role", user.get("role", "user"))]:
            resp.set_cookie(key=key, value=val, secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
        
        resp.delete_cookie("oauth_state", path="/")
        return resp

    except Exception as e:
        logger.exception(f"[GOOGLE SSO] Error: {e}")
        resp = RedirectResponse(url="/login?error=SSO+Error", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp

# --- Routes: Forgot Password (OTP) ---

@router.get("/forgot-password", response_class=HTMLResponse, name="forgot_password_get")
def forgot_password_get(request: Request, message: str = None, error: str = None):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": message, "error": error})

@router.post("/forgot-password", response_class=RedirectResponse)
def forgot_password_post(request: Request, email: EmailStr = Form(...)):
    user = users_collection.find_one({"email": email})
    otp = generate_numeric_otp(OTP_LENGTH)
    otp_hash = hash_otp_for_storage(otp)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

    password_resets_collection.delete_many({"email": email, "used": False})

    password_resets_collection.insert_one({
        "email": email,
        "otp_hash": otp_hash,
        "created_at": now,
        "expires_at": expires_at,
        "used": False,
        "reset_token": None
    })

    if user:
        send_otp_email(email, otp)
    else:
        logger.info(f"OTP requested for non-existent email: {email}")

    return RedirectResponse(url=f"/verify-otp?email={urllib.parse.quote_plus(email)}&message=OTP+sent", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/verify-otp", response_class=HTMLResponse, name="verify_otp_get")
def verify_otp_get(request: Request, email: str = None, message: str = None, error: str = None):
    if not email:
        return RedirectResponse(url="/forgot-password?error=Missing+email", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("verify_otp.html", {"request": request, "email": email, "message": message, "error": error})

@router.post("/verify-otp", response_class=RedirectResponse, name="verify_otp_post")
def verify_otp_post(request: Request, email: EmailStr = Form(...), otp: str = Form(...)):
    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"email": email, "used": False, "expires_at": {"$gt": now}}, sort=[("created_at", -1)])
    
    if not doc or hash_otp_for_storage(otp) != doc["otp_hash"]:
        return RedirectResponse(url=f"/verify-otp?email={urllib.parse.quote_plus(email)}&error=Invalid+OTP", status_code=status.HTTP_303_SEE_OTHER)

    reset_token = uuid.uuid4().hex
    token_expires_at = now + timedelta(minutes=15)

    password_resets_collection.update_one(
        {"_id": doc["_id"]},
        {"$set": {"reset_token": reset_token, "token_expires_at": token_expires_at, "used": False}, "$unset": {"otp_hash": ""}}
    )

    return RedirectResponse(url=f"/reset-password?token={urllib.parse.quote_plus(reset_token)}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/reset-password", response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: str = None, error: str = None):
    if not token:
        return RedirectResponse(url="/forgot-password?error=Missing+token", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@router.post("/reset-password", response_class=RedirectResponse, name="reset_password_post")
def reset_password_post(request: Request, token: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    if password != confirm_password:
        return RedirectResponse(url=f"/reset-password?token={urllib.parse.quote_plus(token)}&error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"reset_token": token, "used": False, "token_expires_at": {"$gt": now}})
    if not doc:
        return RedirectResponse(url="/forgot-password?error=Invalid+token", status_code=status.HTTP_303_SEE_OTHER)

    users_collection.update_one(
        {"email": doc["email"]}, 
        {"$set": {"password_hash": get_password_hash(password), "password_changed_at": datetime.now(timezone.utc)}}
    )
    password_resets_collection.update_one({"_id": doc["_id"]}, {"$set": {"used": True}})

    return RedirectResponse(url="/login?message=Password+reset+success", status_code=status.HTTP_303_SEE_OTHER)

# --- Routes: Protected Pages ---

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, current_user: dict = Depends(get_required_current_user)):
    if current_user.get("role") == "admin":
        return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user,
        "message": request.query_params.get("message")
    })

@router.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(request: Request, current_user: dict = Depends(get_current_admin_user)):
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "user": current_user,
        "message": request.query_params.get("message")
    })

@router.get("/user-profile", response_class=HTMLResponse)
def get_user_profile(request: Request, current_user: dict = Depends(get_required_current_user)):
    user_email = current_user.get("name") # Logic from original code, though email usually safer
    shipments = list(shipments_collection.find({"created_by": user_email}))
    for shipment in shipments:
        shipment["_id"] = str(shipment["_id"])

    return templates.TemplateResponse("user-profile.html", {
        "request": request,
        "user": current_user,
        "shipments": shipments
    })

# --- Routes: API ---

@router.post("/api/login", response_class=JSONResponse)
@limiter.limit("10/minute")
async def api_login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
        expires_delta=token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(token_expires.total_seconds())
    }

@router.get("/me", response_class=JSONResponse)
async def read_users_me(current_user: dict = Depends(get_required_current_user)):
    return current_user

# --- Swagger UI Auth Helper ---

async def get_current_user_from_bearer_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = decode_token(token)
        email = payload.get("sub")
        if not email:
             raise HTTPException(status_code=401, detail="Invalid token")
        
        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {"email": user["email"], "name": user.get("name"), "role": user.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/api/v1/test-swagger-auth", tags=["API Authentication Test"], summary="Test Bearer Auth")
async def test_swagger_auth(current_api_user: dict = Depends(get_current_user_from_bearer_token)):
    return {"message": "Authenticated!", "user": current_api_user}


