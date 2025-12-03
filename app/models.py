from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(150), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    phone = Column(String(20), unique=True, index=True, nullable=False)
    role = Column(String(50), nullable=False, default="user")
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=False)  # start inactive until signup OTP

    totp_secret = None  # ignore if you had TOTP before

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    otps = relationship("OTPCode", back_populates="user")


class OTPCode(Base):
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    code_hash = Column(String(255), nullable=False)
    purpose = Column(String(50), nullable=False)  # "signup" or "login"
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="otps")
