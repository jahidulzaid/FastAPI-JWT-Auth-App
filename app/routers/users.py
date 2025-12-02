# app/routers/users.py
from fastapi import APIRouter, Depends, HTTPException, status

from .. import schemas
from ..deps import get_current_user
from ..models import User

router = APIRouter(tags=["users"])


@router.get("/users/me", response_model=schemas.UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/admin")
def admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins only",
        )
    return {"message": f"Hello admin {current_user.name}"}
