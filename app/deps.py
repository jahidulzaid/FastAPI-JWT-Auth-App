from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import User, OTPCode
from .security import decode_access_token


bearer_scheme = HTTPBearer(auto_error=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials : HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),

)-> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    token = credentials.credentials
    token_data = decode_access_token(token)

    if token_data.user_id in None:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED, 
            detail = "Invalid or expired token",  
        )
    user = db.get(User, token_data.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user