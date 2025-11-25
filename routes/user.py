# app/routers/user.py

import os
from dotenv import load_dotenv
from fastapi import APIRouter, Request, Form, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from pydantic import EmailStr
from datetime import datetime, timedelta, timezone
import requests
# import hashlib # Not used
import logging
from typing import Optional
from fastapi.templating import Jinja2Templates
from jose import JWTError # Import JWTError for specific exception handling

from core.database import users_collection, logins_collection, shipments_collection
from core.auth import (
    verify_password, get_password_hash, create_access_token,
    decode_token, get_current_user, get_required_current_user,
    get_current_admin_user
)
from core.config import (
    RECAPTCHA_SECRET_KEY, RECAPTCHA_SITE_KEY,
    ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM # SECRET_KEY, ALGORITHM not directly used here but by auth functions
)

load_dotenv()
logger = logging.getLogger(__name__)

router = APIRouter(tags=["User Authentication and Web"],)
templates = Jinja2Templates(directory="templates")

# This determines if cookies should be set with the "Secure" flag.
# In production (HTTPS), this should be True. For local HTTP dev or specific EC2 HTTP setups, it might be False.
# Set COOKIE_SECURE_FLAG=False (or any value other than "true", case-insensitive) in your .env or environment for HTTP.
# Defaults to True if the variable is not set or is "true".
COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "False").lower() == "true"

COOKIE_SAMESITE_POLICY = "none" if COOKIE_SECURE_ENABLED else "lax"

# For samesite, "lax" is a good default. If COOKIE_SECURE_ENABLED is False, SameSite="None" cannot be used.
# COOKIE_SAMESITE_POLICY = "lax" if not COOKIE_SECURE_ENABLED else "none"
# if COOKIE_SAMESITE_POLICY == "none" and not COOKIE_SECURE_ENABLED:
    # COOKIE_SAMESITE_POLICY = "lax" # Fallback to lax if secure is false, as "none" requires "secure"

# oauth2_scheme is used for optional token checks and for /api/login
# auto_error=False means it won't raise an error if token is not found, just passes None.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

def verify_recaptcha(token: str) -> bool:
    if not RECAPTCHA_SECRET_KEY: # Allow skipping reCAPTCHA if key is not set (for dev)
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
    except requests.exceptions.RequestException as e: # More specific exception
        logger.error(f"reCAPTCHA verification failed: {str(e)}")
        return False

@router.get("/", response_class=RedirectResponse)
def root(request: Request): # Removed token Depends here, will rely on cookie check in redirect targets
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token) # decode_token raises JWTError on failure
            # Check expiration, decode_token itself should handle expired tokens by raising JWTError
            # if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
            return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        except JWTError: # Token invalid or expired
            # If token is invalid, treat as not logged in, fall through to redirect to login
            # Optionally, clear the bad cookie
            response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token") # Clear potentially bad/expired cookie
            return response
        except Exception as e:
            logger.error(f"Error during root token check: {str(e)}")
            # Fall through to login
            pass
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/login", response_class=HTMLResponse)
def get_login(
    request: Request,
    error: str = None,
    message: str = None
):
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            # if payload.get("exp") and datetime.fromtimestamp(payload["exp"], timezone.utc) > datetime.now(timezone.utc):
            # If token is valid, redirect
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except JWTError:
             # Invalid token, show login page, maybe clear cookie
            pass # Fall through to show login page
        except Exception as e:
            logger.error(f"Token validation error on /login GET: {str(e)}")
            pass # Fall through

    return templates.TemplateResponse("login.html", {
        "request": request,
        "site_key": RECAPTCHA_SITE_KEY,
        "error": error,
        "message": message
    })

@router.post("/login", response_class=RedirectResponse)
async def post_login(
    request: Request, # Keep request for potential future use (e.g. IP logging)
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
        return RedirectResponse(url="/login?error=Invalid+credentials", status_code=status.HTTP_303_SEE_OTHER)

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

    # Set cookies with configurable Secure and SameSite attributes
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True, # Crucial for security: JS can't access
        secure=COOKIE_SECURE_ENABLED,
        max_age=int(token_expires.total_seconds()), # max_age is in seconds
        samesite=COOKIE_SAMESITE_POLICY,
        path="/"
    )
    # User info cookies - if JS needs them, HttpOnly must be False.
    # Consider if these are truly needed as cookies or if /me endpoint is sufficient.
    response.set_cookie(key="user_name", value=user.get("name", ""), secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
    response.set_cookie(key="user_email", value=user["email"], secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
    response.set_cookie(key="user_role", value=user.get("role", "user"), secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
    return response

@router.post("/api/login", response_class=JSONResponse) # Ensure JSONResponse for API
async def api_login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Note: This API login does not have reCAPTCHA. Add if needed for public APIs.
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        # Log failed API login attempt
        logins_collection.insert_one({
            "email": form_data.username,
            "login_time": datetime.now(timezone.utc),
            "status": "failed_api_attempt"
            # "ip_address": Can't get from form_data directly, would need Request object
        })
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
        "status": "success_api"
    })

    return { # Return JSONResponse content
        "access_token": access_token,
        "token_type": "bearer",
        "user_info": {
            "email": user["email"],
            "name": user.get("name"),
            "role": user.get("role", "user")
        },
        "expires_in": int(token_expires.total_seconds())
    }


@router.get("/signup", response_class=HTMLResponse)
def get_signup(
    request: Request,
    error: str = None
):
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(
                url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except JWTError:
            pass # Fall through
        except Exception as e:
            logger.error(f"Token validation error on /signup GET: {str(e)}")
            pass
    return templates.TemplateResponse("signup.html", {
        "request": request,
        "error": error,
        "site_key": RECAPTCHA_SITE_KEY # Assuming reCAPTCHA also on signup
    })

# --- START OTP-based password reset implementation ---
import os
import smtplib
import hashlib
import secrets
import uuid
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from urllib.parse import quote_plus
from pydantic import EmailStr
from fastapi import Form

# Ensure these are imported already at top of file; if not, add them.
# from core.database import users_collection, logins_collection
# You will need a new collection for password reset records:
password_resets_collection = getattr(globals(), "password_resets_collection", None)
if password_resets_collection is None:
    # fallback: create alias to MongoDB collection from your core.database module
    try:
        from core.database import db  # if you have central db object
        password_resets_collection = db["password_resets"]
    except Exception:
        # If you don't have 'db', use users_collection's database
        password_resets_collection = users_collection.database.get_collection("password_resets")

# Config from env (defaults)
OTP_LENGTH = int(os.getenv("OTP_LENGTH", "6"))
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))
OTP_HASH_SECRET = os.getenv("OTP_HASH_SECRET", os.getenv("SECRET_KEY", "change_this_secret"))

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "0") or 0)
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "no-reply@example.com")

def generate_numeric_otp(length: int = 6) -> str:
    """Generate a secure numeric OTP of given length."""
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp_for_storage(otp: str) -> str:
    """Return a SHA256 HMAC-like hash using OTP_HASH_SECRET (not reversible)."""
    h = hashlib.sha256()
    h.update((OTP_HASH_SECRET + otp).encode("utf-8"))
    return h.hexdigest()

def send_otp_email(to_email: str, otp: str) -> bool:
    """Send OTP via SMTP. If SMTP isn't configured, log the OTP and return True for dev."""
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

@router.get("/forgot-password", response_class=HTMLResponse, name="forgot_password_get")
def forgot_password_get(request: Request, message: str = None, error: str = None):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "message": message, "error": error})

@router.post("/forgot-password", response_class=RedirectResponse)
def forgot_password_post(request: Request, email: EmailStr = Form(...)):
    """
    User requests an OTP for resetting password.
    We always return the same user-facing message to avoid enumeration.
    """
    user = users_collection.find_one({"email": email})
    # Always generate OTP and persist record to maintain consistent timing (but we only send if user exists)
    otp = generate_numeric_otp(OTP_LENGTH)
    otp_hash = hash_otp_for_storage(otp)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)

    # Single-use semantics: remove old pending resets for this email
    password_resets_collection.delete_many({"email": email, "used": False})

    reset_doc = {
        "email": email,
        "otp_hash": otp_hash,
        "created_at": now,
        "expires_at": expires_at,
        "used": False,
        "reset_token": None  # will be created after successful OTP verification
    }
    password_resets_collection.insert_one(reset_doc)

    if user:
        ok = send_otp_email(email, otp)
        if not ok:
            logger.warning(f"Failed to send OTP to {email} but returning generic message.")
    else:
        logger.info(f"OTP requested for non-existent email: {email} (no email sent)")

    # Redirect to verify OTP page (user-facing message generic)
    return RedirectResponse(url=f"/verify-otp?email={quote_plus(email)}&message=OTP+sent+if+account+exists", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/verify-otp", response_class=HTMLResponse, name="verify_otp_get")
def verify_otp_get(request: Request, email: str = None, message: str = None, error: str = None):
    if not email:
        return RedirectResponse(url="/forgot-password?error=Missing+email", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("verify_otp.html", {"request": request, "email": email, "message": message, "error": error})

@router.post("/verify-otp", response_class=RedirectResponse, name="verify_otp_post")
def verify_otp_post(request: Request, email: EmailStr = Form(...), otp: str = Form(...)):
    """
    Verify OTP submitted by user. If valid, create a one-time reset_token and redirect to reset form.
    """
    now = datetime.now(timezone.utc)
    # find the most recent reset record for this email that's unused and not expired
    doc = password_resets_collection.find_one({"email": email, "used": False, "expires_at": {"$gt": now}}, sort=[("created_at", -1)])
    if not doc:
        return RedirectResponse(url=f"/verify-otp?email={quote_plus(email)}&error=Invalid+or+expired+OTP", status_code=status.HTTP_303_SEE_OTHER)

    if hash_otp_for_storage(otp) != doc["otp_hash"]:
        # allow friendly message but avoid too specific details
        # optional: increment failure counter or rate-limit here
        return RedirectResponse(url=f"/verify-otp?email={quote_plus(email)}&error=Invalid+OTP", status_code=status.HTTP_303_SEE_OTHER)

    # OTP valid — create a one-time reset token, set a short expiry for token (e.g., 15 min)
    reset_token = uuid.uuid4().hex
    token_expires_at = now + timedelta(minutes=int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "15")))

    password_resets_collection.update_one(
        {"_id": doc["_id"]},
        {"$set": {"reset_token": reset_token, "token_expires_at": token_expires_at, "used": False}, "$unset": {"otp_hash": ""}}  # remove OTP hash to avoid reuse
    )

    # Redirect to reset-password page with token in query (token is single-use and stored server-side)
    return RedirectResponse(url=f"/reset-password?token={quote_plus(reset_token)}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/reset-password", response_class=HTMLResponse, name="reset_password_get")
def reset_password_get(request: Request, token: str = None, error: str = None):
    if not token:
        return RedirectResponse(url="/forgot-password?error=Missing+token", status_code=status.HTTP_303_SEE_OTHER)

    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"reset_token": token, "used": False, "token_expires_at": {"$gt": now}})
    if not doc:
        return RedirectResponse(url="/forgot-password?error=Invalid+or+expired+token", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@router.post("/reset-password", response_class=RedirectResponse, name="reset_password_post")
def reset_password_post(request: Request, token: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    if password != confirm_password:
        return RedirectResponse(url=f"/reset-password?token={quote_plus(token)}&error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    now = datetime.now(timezone.utc)
    doc = password_resets_collection.find_one({"reset_token": token, "used": False, "token_expires_at": {"$gt": now}})
    if not doc:
        return RedirectResponse(url="/forgot-password?error=Invalid+or+expired+token", status_code=status.HTTP_303_SEE_OTHER)

    email = doc["email"]
    user = users_collection.find_one({"email": email})
    if not user:
        # safety: if user doesn't exist, mark reset doc used and return generic message
        password_resets_collection.update_one({"_id": doc["_id"]}, {"$set": {"used": True}})
        logger.info(f"Password reset attempted for non-existent user {email}")
        return RedirectResponse(url="/login?message=Password+reset+completed.+Please+log+in.", status_code=status.HTTP_303_SEE_OTHER)

    # update password
    new_hash = get_password_hash(password)
    users_collection.update_one({"email": email}, {"$set": {"password_hash": new_hash, "password_changed_at": datetime.now(timezone.utc)}})

    # mark the reset doc used
    password_resets_collection.update_one({"_id": doc["_id"]}, {"$set": {"used": True}})

    # log the event
    logins_collection.insert_one({
        "email": email,
        "login_time": datetime.now(timezone.utc),
        "status": "password_reset_via_otp"
    })

    return RedirectResponse(url="/login?message=Password+has+been+reset.+Please+log+in.", status_code=status.HTTP_303_SEE_OTHER)

# --- END OTP-based password reset implementation ---


@router.post("/signup", response_class=RedirectResponse)
def post_signup(
    request: Request, # Added request for consistency, potential IP logging
    fullname: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    # g_recaptcha_response: str = Form(..., alias="g-recaptcha-response"), # Add if reCAPTCHA on signup
):
    # Example: if verify_recaptcha and not verify_recaptcha(g_recaptcha_response):
    #     return RedirectResponse(url="/signup?error=reCAPTCHA+failed", status_code=303)

    access_token = request.cookies.get("access_token") # Check if already logged in
    if access_token:
        try:
            payload = decode_token(access_token)
            return RedirectResponse(url="/admin-dashboard" if payload.get("role") == "admin" else "/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        except JWTError:
            pass # Let signup proceed if token is bad
        except Exception:
            pass


    if password != confirm_password:
        return RedirectResponse(url="/signup?error=Passwords+do+not+match", status_code=status.HTTP_303_SEE_OTHER)

    if users_collection.find_one({"email": email}):
        return RedirectResponse(url="/signup?error=Email+already+registered", status_code=status.HTTP_303_SEE_OTHER)

    # Determine role based on email domain, ensure this logic is secure and intended.
    # E.g. "@admin.com" is a simple check, might need more robust mechanism for prod.
    role = "admin" if email.endswith(os.getenv("ADMIN_EMAIL_DOMAIN", "@admin.com")) else "user"
    user_data = {
        "name": fullname,
        "email": email,
        "password_hash": get_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc),
        "email_verified": False # Optional: add email verification flow
    }

    users_collection.insert_one(user_data)
    # Consider auto-login after signup or sending verification email.
    # For now, redirect to login with a success message.
    return RedirectResponse(url="/login?message=Account+created+successfully.+Please+log+in.", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/logout", response_class=RedirectResponse)
def logout(request: Request): # request object not strictly needed unless logging IP, etc.
    response = RedirectResponse(url="/login?message=Logged+out+successfully", status_code=status.HTTP_303_SEE_OTHER)
    # Clear all relevant cookies
    response.delete_cookie("access_token", path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    response.delete_cookie("user_email", path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    response.delete_cookie("user_role", path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    response.delete_cookie("user_name", path="/", secure=COOKIE_SECURE_ENABLED, samesite=COOKIE_SAMESITE_POLICY)
    return response

@router.get("/me", response_class=JSONResponse) # Explicitly JSONResponse for an API endpoint
async def read_users_me(current_user: dict = Depends(get_required_current_user)):
    # current_user from get_required_current_user already contains email, name, role
    return current_user

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(
    request: Request,
    current_user: dict = Depends(get_required_current_user), # Ensures user is logged in
):
    if current_user.get("role") == "admin": # This check is also in get_current_admin_user
        return RedirectResponse(url="/admin-dashboard", status_code=status.HTTP_303_SEE_OTHER)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": current_user, # Pass the whole user dict for more flexibility in template
        "name": current_user.get("name"), # Kept for compatibility if template uses it directly
        "message": request.query_params.get("message")
    })

@router.get("/user-profile", response_class=HTMLResponse)
def get_user_profile(
    request: Request,
    current_user: dict = Depends(get_required_current_user),
):
    # Use email for querying shipments as it's a more reliable unique identifier
    user_email = current_user.get("name")
    if not user_email: # Should not happen if get_required_current_user works
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User email not found in token.")

    shipments = list(shipments_collection.find({"created_by": user_email}))
    for shipment in shipments:
        shipment["_id"] = str(shipment["_id"]) # Convert ObjectId for template

    return templates.TemplateResponse("user-profile.html", {
        "request": request,
        "user": current_user,
        "shipments": shipments
    })

@router.get("/admin-dashboard", response_class=HTMLResponse)
def get_admin_dashboard(
    request: Request,
    current_user: dict = Depends(get_current_admin_user), # Ensures user is admin
):
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "user": current_user, # Pass whole user dict
        "name": current_user.get("name"), # Kept for compatibility
        "message": request.query_params.get("message") # Allow messages here too
    })

# ---- MINIMAL ADDITION FOR SWAGGER UI "AUTHORIZE" BUTTON ----
# This dependency function processes a Bearer token obtained via oauth2_scheme
async def get_current_user_from_bearer_token(token: str = Depends(oauth2_scheme)):
    if token is None: # auto_error=False in OAuth2PasswordBearer means token can be None
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated via Bearer token (no token provided)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(token)
        email: Optional[str] = payload.get("sub") # Use Optional for type hinting
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload (missing subject)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_from_db = users_collection.find_one({"email": email})
        if user_from_db is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found for token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return {
            "email": user_from_db.get("email"),
            "name": user_from_db.get("name"),
            "role": user_from_db.get("role", "user")
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate Bearer token (e.g., expired, invalid)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Error processing bearer token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing token",
            headers={"WWW-Authenticate": "Bearer"}, # It's good practice to include this for 401/500 related to auth
        )

@router.get("/api/v1/test-swagger-auth",
            tags=["API Authentication Test"], # New tag for this specific endpoint
            summary="Test Bearer Token Auth (for Swagger UI 'Authorize' Button)",
            response_model=dict # Example response
            )
async def test_swagger_auth_endpoint_v1(
    # This dependency makes FastAPI include oauth2_scheme in openapi.json
    current_api_user: dict = Depends(get_current_user_from_bearer_token)
):
  
    return {
        "message": "Successfully authenticated via Bearer token for API v1 test!",
        "authenticated_user_details": current_api_user
    }
# ---- END OF MINIMAL ADDITION ----

import secrets
import urllib.parse
from typing import Dict
# requests is already imported above, used for reCAPTCHA; reuse it

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")
GOOGLE_OAUTH_SCOPES = os.getenv("GOOGLE_OAUTH_SCOPES", "openid email profile")
GOOGLE_OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"


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

# --- Google SSO: single login route + callback (replace duplicates with this) ---
import secrets
from fastapi.responses import RedirectResponse

@router.get("/auth/google/login", name="google_login", response_class=RedirectResponse)
def google_login(request: Request):
    """
    Start Google OAuth: generate state, set it in a cookie and redirect to Google consent.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("[GOOGLE SSO] Missing client id/secret in env")
        return RedirectResponse(url="/login?error=Google+SSO+not+configured", status_code=status.HTTP_303_SEE_OTHER)

    # generate state and auth URL
    state = secrets.token_urlsafe(32)
    auth_url = build_google_auth_url(state)

    # log for debugging
    logger.info(f"[GOOGLE SSO] Redirecting to Google. auth_url startswith: {auth_url[:120]}...")
    logger.debug(f"[GOOGLE SSO] Generated oauth state: {state}")

    # set cookie for state. Use secure & samesite from your config.
    # For local dev over http keep COOKIE_SECURE_ENABLED=False (your .env). samesite='lax' is safe.
    # Keep httponly=True for security. If debugging cookie visibility, temporarily set httponly=False.
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


import httpx
import os

async def exchange_code_for_tokens(code: str, redirect_uri: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, data=data)
        response.raise_for_status()
        return response.json()  # Contains access_token, id_token, etc.


async def get_google_userinfo(access_token: str):
    userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}

    async with httpx.AsyncClient() as client:
        response = await client.get(userinfo_url, headers=headers)
        response.raise_for_status()
        return response.json()  # Contains email, picture, name, etc.


@router.get("/auth/google/callback", response_class=RedirectResponse)
def google_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """
    Validate OAuth state, exchange code for tokens, fetch userinfo, sign in/create user,
    then set our JWT cookie and redirect to dashboard/admin.
    """
    # helpful logs for debugging
    logger.info(f"[GOOGLE SSO] callback called. query params: {dict(request.query_params)}")
    logger.debug(f"[GOOGLE SSO] raw Cookie header: {request.headers.get('cookie')!r}")

    if error:
        logger.warning(f"[GOOGLE SSO] Callback returned error param: {error}")
        return RedirectResponse(url="/login?error=Google+login+failed", status_code=status.HTTP_303_SEE_OTHER)

    if not code or not state:
        logger.warning("[GOOGLE SSO] Missing code or state in callback")
        return RedirectResponse(url="/login?error=Missing+code+or+state", status_code=status.HTTP_303_SEE_OTHER)

    # read cookie state and compare
    cookie_state = request.cookies.get("oauth_state")
    logger.debug(f"[GOOGLE SSO] cookie_state={cookie_state!r} callback_state={state!r}")

    if not cookie_state:
        # cookie missing — common causes: secure flag on http, domain mismatch, different host (127.0.0.1 vs localhost)
        logger.warning("[GOOGLE SSO] oauth_state cookie missing in callback request.")
        # Provide a useful hint for developer in the UI (no secrets leaked)
        return RedirectResponse(url="/login?error=Missing+oauth_state+cookie", status_code=status.HTTP_303_SEE_OTHER)

    if cookie_state != state:
        logger.warning("[GOOGLE SSO] oauth_state mismatch (cookie != callback param)")
        # clear cookie and return
        resp = RedirectResponse(url="/login?error=Invalid+OAuth+state", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp

    # state validated, cleanup cookie to prevent reuse
    # (we'll set our normal auth cookies after successful token exchange)
    # Exchange code for tokens
    try:
        token_resp = exchange_code_for_tokens(code)
        access_token_google = token_resp.get("access_token")
        if not access_token_google:
            logger.error(f"[GOOGLE SSO] token exchange response missing access_token: {token_resp}")
            resp = RedirectResponse(url="/login?error=Google+token+exchange+failed", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # Fetch user info from Google
        userinfo = get_google_userinfo(access_token_google)
        email = userinfo.get("email")
        name = userinfo.get("name") or userinfo.get("given_name") or (email.split("@")[0] if email else "Unknown")

        if not email:
            logger.error(f"[GOOGLE SSO] Google userinfo missing email: {userinfo}")
            resp = RedirectResponse(url="/login?error=Google+profile+missing+email", status_code=status.HTTP_303_SEE_OTHER)
            resp.delete_cookie("oauth_state", path="/")
            return resp

        # Find or create local user
        user = users_collection.find_one({"email": email})
        if not user:
            new_user = {
                "name": name,
                "email": email,
                "password_hash": "",  # SSO only
                "role": "user",
                "created_at": datetime.now(timezone.utc),
                "email_verified": True,
                "sso_provider": "google",
                "sso_sub": userinfo.get("sub")
            }
            users_collection.insert_one(new_user)
            user = users_collection.find_one({"email": email})

        # Log
        logins_collection.insert_one({
            "email": email,
            "login_time": datetime.now(timezone.utc),
            "status": "success_google_sso",
            "ip_address": request.client.host if request.client else "unknown"
        })

        # Create our JWT token and set cookies (same as your post_login)
        token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "role": user.get("role", "user"), "name": user.get("name")},
            expires_delta=token_expires
        )

        redirect_url = "/admin-dashboard" if user.get("role") == "admin" else "/dashboard"
        resp = RedirectResponse(url=f"{redirect_url}?message=Successfully+logged+in+with+Google", status_code=status.HTTP_303_SEE_OTHER)

        resp.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=COOKIE_SECURE_ENABLED,
            max_age=int(token_expires.total_seconds()),
            samesite=COOKIE_SAMESITE_POLICY,
            path="/"
        )
        resp.set_cookie(key="user_name", value=user.get("name", ""), secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
        resp.set_cookie(key="user_email", value=user["email"], secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))
        resp.set_cookie(key="user_role", value=user.get("role", "user"), secure=COOKIE_SECURE_ENABLED, httponly=False, samesite=COOKIE_SAMESITE_POLICY, path="/", max_age=int(token_expires.total_seconds()))

        # clear oauth_state (already validated)
        resp.delete_cookie("oauth_state", path="/")

        return resp

    except requests.exceptions.RequestException as e:
        logger.error(f"[GOOGLE SSO] Network error during token exchange/userinfo: {e}")
        resp = RedirectResponse(url="/login?error=Google+SSO+network+error", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp
    except Exception as e:
        logger.exception(f"[GOOGLE SSO] Unexpected error in callback: {e}")
        resp = RedirectResponse(url="/login?error=Google+SSO+failed", status_code=status.HTTP_303_SEE_OTHER)
        resp.delete_cookie("oauth_state", path="/")
        return resp
# --- end Google SSO functions ---
