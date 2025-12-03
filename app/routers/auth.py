# app/routers/auth.py
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas, security
from ..deps import get_db
from ..email_utils import send_email

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# -------- SIGNUP with EMAIL OTP --------

@router.post("/signup", response_model=schemas.SignupResponse, status_code=201)
def signup(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    # Uniqueness checks
    existing_email = (
        db.query(models.User).filter(models.User.email == user_in.email).first()
    )
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    existing_phone = (
        db.query(models.User).filter(models.User.phone == user_in.phone).first()
    )
    if existing_phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone already registered",
        )

    hashed_pw = security.hash_password(user_in.password)

    user = models.User(
        name=user_in.name,
        email=user_in.email,
        phone=user_in.phone,
        role=user_in.role,
        hashed_password=hashed_pw,
        is_active=False,  # will be activated after OTP verification
    )

    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or phone already exists",
        )

    db.refresh(user)

    # generate signup OTP
    otp_code = security.generate_otp_code()
    otp_hash = security.hash_otp(otp_code)
    expires_at = security.otp_expires_in(minutes=10)

    otp = models.OTPCode(
        user_id=user.id,
        code_hash=otp_hash,
        purpose="signup",
        expires_at=expires_at,
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)

    # send OTP to email
    subject = "Your Signup OTP Code"
    body = f"Hello {user.name},\n\nYour signup OTP code is: {otp_code}\n\nIt will expire in 10 minutes."
    send_email(user.email, subject, body)

    return schemas.SignupResponse(
        otp_id=otp.id,
        detail="Signup OTP sent to your email",
    )


@router.post("/signup/verify")
def signup_verify(body: schemas.SignupOTPVerify, db: Session = Depends(get_db)):
    otp = db.query(models.OTPCode).filter(models.OTPCode.id == body.otp_id).first()

    if not otp or otp.purpose != "signup":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP request",
        )

    if otp.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP already used",
        )

    if otp.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired",
        )

    if not security.verify_otp(body.otp_code, otp.code_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code",
        )

    # Mark OTP used and activate user
    otp.is_used = True
    user = db.query(models.User).filter(models.User.id == otp.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found for this OTP",
        )

    user.is_active = True
    db.add(otp)
    db.add(user)
    db.commit()

    return {"detail": "Signup verified, account activated."}


# -------- LOGIN with EMAIL OTP --------

@router.post("/login/start", response_model=schemas.LoginOTPStartResponse)
def login_start(
    body: schemas.LoginOTPStart,
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.email == body.email).first()

    if not user or not security.verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not activated",
        )

    otp_code = security.generate_otp_code()
    otp_hash = security.hash_otp(otp_code)
    expires_at = security.otp_expires_in(minutes=5)

    otp = models.OTPCode(
        user_id=user.id,
        code_hash=otp_hash,
        purpose="login",
        expires_at=expires_at,
    )
    db.add(otp)
    db.commit()
    db.refresh(otp)

    subject = "Your Login OTP Code"
    body_text = f"Hello {user.name},\n\nYour login OTP code is: {otp_code}\n\nIt will expire in 5 minutes."
    send_email(user.email, subject, body_text)

    return schemas.LoginOTPStartResponse(
        otp_id=otp.id,
        detail="Login OTP sent to your email",
    )


@router.post("/login/verify", response_model=schemas.Token)
def login_verify(body: schemas.LoginOTPVerify, db: Session = Depends(get_db)):
    otp = db.query(models.OTPCode).filter(models.OTPCode.id == body.otp_id).first()

    if not otp or otp.purpose != "login":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP request",
        )

    if otp.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP already used",
        )

    if otp.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP expired",
        )

    if not security.verify_otp(body.otp_code, otp.code_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code",
        )

    user = db.query(models.User).filter(models.User.id == otp.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    otp.is_used = True
    db.add(otp)

    access_token = security.create_access_token(data={"sub": str(user.id)})
    db.commit()

    return {"access_token": access_token, "token_type": "bearer"}
