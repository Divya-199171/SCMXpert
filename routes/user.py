# app/routers/user.py

import os
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from pydantic import EmailStr
from datetime import datetime, timedelta, timezone
import requests
import hashlib
import logging
from typing import Optional
from fastapi.templating import Jinja2Templates
from core.database import users_collection, logins_collection
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    decode_token, get_current_user, get_required_current_user, 
    get_current_admin_user
)
from core.config import (
    RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY, 
    ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM
)

load_dotenv()
logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="templates")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

def verify_recaptcha(token: str) -> bool:
    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": token},
            timeout=5
        )
        response.raise_for_status()
        return response.json().get("success", False)
    except Exception as e:
        logger.error(f"reCAPTCHA verification failed: {str(e)}")
        return False

@router.get("/", response_class=RedirectResponse)
def root(token: Optional[str] = Depends(oauth2_scheme)):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard")
        except Exception:
            pass
    return RedirectResponse(url="/login")

@router.get("/login", response_class=HTMLResponse)
def get_login(
    request: Request, 
    error: str = None, 
    message: str = None,
    token: Optional[str] = Depends(oauth2_scheme)
):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard")
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            pass
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "error": error,
        "message": message
    })

@router.post("/login", response_class=RedirectResponse)
async def post_login(
    request: Request,
    username: EmailStr = Form(...),
    password: str = Form(...),
    g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"),
    token: Optional[str] = Depends(oauth2_scheme)
):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard")
        except Exception:
            pass

    if not verify_recaptcha(g_recaptcha_response):
        return RedirectResponse(url="/login?error=reCAPTCHA+failed", status_code=303)

    try:
        user = users_collection.find_one({"email": username})
        if not user or not verify_password(password, user["password_hash"]):
            logins_collection.insert_one({
                "email": username,
                "login_time": datetime.now(timezone.utc),
                "status": "failed"
            })
            return RedirectResponse(url="/login?error=Invalid+credentials", status_code=303)

        token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
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
            secure=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            samesite="lax",
            path="/"
        )
        response.set_cookie(key="user_name", value=user.get("name", ""))
        response.set_cookie(key="user_email", value=user["email"])
        response.set_cookie(key="user_role", value=user.get("role", "user"))
        return response

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return RedirectResponse(url="/login?error=Login+failed", status_code=303)

@router.post("/api/login")
async def api_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    token: Optional[str] = Depends(oauth2_scheme)
):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                user = users_collection.find_one({"email": payload.get("sub")})
                if user:
                    return {
                        "access_token": token,
                        "token_type": "bearer",
                        "user_info": {
                            "email": user["email"],
                            "name": user.get("name"),
                            "role": user.get("role", "user")
                        }
                    }
        except Exception:
            pass

    try:
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

        logins_collection.insert_one({
            "email": form_data.username,
            "login_time": datetime.now(timezone.utc),
            "status": "success"
        })

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_info": {
                "email": user["email"],
                "name": user.get("name"),
                "role": user.get("role", "user")
            }
        }

    except Exception as e:
        logger.error(f"API login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )

@router.get("/signup", response_class=HTMLResponse)
def get_signup(
    request: Request, 
    error: str = None,
    token: Optional[str] = Depends(oauth2_scheme)
):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard")
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
    token: Optional[str] = Depends(oauth2_scheme)
):
    if token:
        try:
            payload = decode_token(token)
            if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
                return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard")
        except Exception:
            pass

    try:
        if password != confirm_password:
            return RedirectResponse(url="/signup?error=Passwords+do+not+match", status_code=303)

        if users_collection.find_one({"email": email}):
            return RedirectResponse(url="/signup?error=Email+already+registered", status_code=303)

        role = "admin" if email.endswith("@admin.com") else "user"
        user_data = {
            "name": fullname,
            "email": email,
            "password_hash": get_password_hash(password),
            "role": role,
            "created_at": datetime.now(timezone.utc)
        }

        users_collection.insert_one(user_data)
        return RedirectResponse(url="/login?message=Account+created+successfully", status_code=303)

    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return RedirectResponse(url="/signup?error=Registration+failed", status_code=303)

@router.get("/logout", response_class=RedirectResponse)
def logout(token: Optional[str] = Depends(oauth2_scheme)):
    response = RedirectResponse(url="/login?message=Logged+out+successfully")
    response.delete_cookie("access_token")
    response.delete_cookie("user_email")
    response.delete_cookie("user_role")
    response.delete_cookie("user_name")
    return response

@router.get("/me")
async def read_users_me(
    current_user: dict = Depends(get_current_user),
    token: Optional[str] = Depends(oauth2_scheme)
):
    return current_user

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(
    request: Request, 
    current_user: dict = Depends(get_required_current_user),
    token: Optional[str] = Depends(oauth2_scheme)
):
    if current_user.get("role") == "admin":
        return RedirectResponse(url="/admin-dashboard")
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "name": current_user.get("name"),
        "message": request.query_params.get("message")
    })

@router.get("/user-profile", response_class=HTMLResponse)
def get_user_profile(
    request: Request, 
    current_user: dict = Depends(get_required_current_user),
    token: Optional[str] = Depends(oauth2_scheme)
):
    return templates.TemplateResponse("user-profile.html", {
        "request": request,
        "user": current_user
    })

@router.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(
    request: Request, 
    current_user: dict = Depends(get_current_admin_user),
    token: Optional[str] = Depends(oauth2_scheme)
):
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "name": current_user.get("name")
    })