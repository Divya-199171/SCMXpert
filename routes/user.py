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
COOKIE_SECURE_ENABLED = os.getenv("COOKIE_SECURE_FLAG", "True").lower() == "true"
# For samesite, "lax" is a good default. If COOKIE_SECURE_ENABLED is False, SameSite="None" cannot be used.
COOKIE_SAMESITE_POLICY = "lax" if not COOKIE_SECURE_ENABLED else "none"
if COOKIE_SAMESITE_POLICY == "none" and not COOKIE_SECURE_ENABLED:
    COOKIE_SAMESITE_POLICY = "lax" # Fallback to lax if secure is false, as "none" requires "secure"

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
    # More robust check using get_current_user to see if already logged in via cookie
    # This avoids decoding token manually here if auth logic is complex.
    # However, for a simple root redirect, checking cookie presence might be enough,
    # but get_current_user is more aligned with how other protected routes work.
    # Let's try a lightweight check for the cookie first.
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
    """
    This endpoint requires Bearer token authentication.
    It's added to ensure the 'Authorize' button appears in Swagger UI.
    Use the 'Authorize' button, log in via the /api/login flow,
    and then execute this endpoint.
    """
    return {
        "message": "Successfully authenticated via Bearer token for API v1 test!",
        "authenticated_user_details": current_api_user
    }
# ---- END OF MINIMAL ADDITION ----