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


# otp
# ---- OTP-related schemas ----

class SignupOTPVerify(BaseModel):
    otp_id: int
    otp_code: str = Field(..., min_length=6, max_length=6)


class SignupResponse(BaseModel):
    otp_id: int
    detail: str = "Signup OTP sent to email"


class LoginOTPStart(BaseModel):
    email: EmailStr
    password: str


class LoginOTPStartResponse(BaseModel):
    otp_id: int
    detail: str = "Login OTP sent to email"


class LoginOTPVerify(BaseModel):
    otp_id: int
    otp_code: str = Field(..., min_length=6, max_length=6)