from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from core.database import users_collection

# ------------------ Password hashing ------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# ------------------ JWT Models & Token handling ------------------
class TokenData(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[str] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

# ------------------ OAuth2 Scheme (for Swagger / API) ------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

# ------------------ Dependencies ------------------
async def get_current_user(
    request: Request,
    bearer_token: str = Depends(oauth2_scheme)
) -> Optional[dict]:
    """
    Get current user from cookie (web login) or Bearer token (API clients).
    """

    # 1. Try cookie first
    token = request.cookies.get("access_token")

    # 2. Fallback to Bearer token
    if not token and bearer_token:
        token = bearer_token

    if not token:
        return None

    try:
        payload = decode_token(token)
        email = payload.get("sub")
        role = payload.get("role")
        name = payload.get("name")

        if not email:
            return None

        user = users_collection.find_one({"email": email})
        if not user:
            return None

        return {"email": email, "name": name, "role": role}

    except JWTError:
        return None


async def get_required_current_user(
    request: Request,
    bearer_token: str = Depends(oauth2_scheme)
) -> dict:
    """
    Force authentication – returns current user or raises 401.
    """
    user = await get_current_user(request, bearer_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_admin_user(current_user: dict = Depends(get_required_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
