from typing import Optional

from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    name: str = Field(..., example="John Doe", max_length=150)
    email: EmailStr
    phone: str = Field(..., example="+1234567890", max_length=20)
    role: Optional[str] = Field(default="user", max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr
    phone: str
    role: str

    class Config:
        from_attributes = True
    
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    
class TokenData(BaseModel):
    user_id: Optional[int] = None