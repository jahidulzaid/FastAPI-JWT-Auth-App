from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
import random

from .config import settings
from .schemas import TokenData

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str)->str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str)-> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_minutes: Optional[int] = None)->str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc)+timedelta(
        minutes = expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
        
    )
    return encoded_jwt

def decode_access_token(token: str)-> TokenData:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        user_id: int = payload.get("sub")
        if user_id is None:
            return TokenData()
        return TokenData(user_id = int(user_id))
    except JWTError:
        return TokenData()
    



# -------- OTP-specific helpers --------

def generate_otp_code(length: int = 6) -> str:
    """Generate a numeric OTP code like '483920'."""
    min_val = 10 ** (length - 1)
    max_val = (10 ** length) - 1
    return str(random.randint(min_val, max_val))


def hash_otp(code: str) -> str:
    return pwd_context.hash(code)


def verify_otp(code: str, hashed: str) -> bool:
    return pwd_context.verify(code, hashed)


def otp_expires_in(minutes: int = 5) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes)