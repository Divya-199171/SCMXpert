# core/auth.py

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import RedirectResponse # <--- ADD THIS IMPORT
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from core.database import users_collection


# --- Password hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# --- JWT Models & Token handling ---
class TokenData(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise e


# --- Dependencies ---
async def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        payload = decode_token(token)
        email = payload.get("sub")
        role = payload.get("role")
        name = payload.get("name")

        if email is None:
            # This is an invalid token structure if 'sub' is missing.
            # Create a response to clear cookies and redirect.
            response = RedirectResponse(url="/login?error=Invalid+token+payload", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token")
            response.delete_cookie("user_email")
            response.delete_cookie("user_role")
            response.delete_cookie("user_name")
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail="Invalid token payload: Missing email.",
                headers=response.headers, # Use headers from the RedirectResponse
            )

        user = users_collection.find_one({"email": email})
        if not user:
            # User for whom token was issued no longer exists.
            response = RedirectResponse(url="/login?error=User+not+found.+Please+log+in+again.", status_code=status.HTTP_303_SEE_OTHER)
            response.delete_cookie("access_token")
            response.delete_cookie("user_email")
            response.delete_cookie("user_role")
            response.delete_cookie("user_name")
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                detail="User not found.",
                headers=response.headers, # Use headers from the RedirectResponse
            )
        
        return {"email": email, "name": name, "role": role}
    
    except JWTError:
        # Token is invalid (expired, malformed, wrong signature)
        response = RedirectResponse(url="/login?error=Session+expired+or+invalid.", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("access_token")
        response.delete_cookie("user_email")
        response.delete_cookie("user_role")
        response.delete_cookie("user_name")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Session expired or invalid. Please log in again.",
            headers=response.headers, # Use headers from the RedirectResponse
        )


async def get_required_current_user(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user is None:
        # get_current_user itself should have handled the redirect for cookie-related issues.
        # This case now means 'no token at all' was initially present.
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Authentication required. Please log in.",
            headers={"Location": "/login?error=Authentication+required"},
        )
    return current_user


async def get_current_admin_user(current_user: dict = Depends(get_required_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Admin privileges required.",
            headers={"Location": "/dashboard?error=Admin+access+required"}
        )
    return current_user