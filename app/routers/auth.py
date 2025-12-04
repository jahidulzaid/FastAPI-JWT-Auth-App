# app/routers/auth.py
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models, schemas, security
from ..deps import get_db
from ..email_utils import send_email


def get_current_utc_time():
    """Get current UTC time, handling both timezone-aware and naive datetimes."""
    now = datetime.now(timezone.utc)
    # Return timezone-naive for SQLite compatibility
    return now.replace(tzinfo=None)

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
    try:
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

        # Handle both timezone-aware and naive datetimes
        current_time = get_current_utc_time()
        expires_time = otp.expires_at.replace(tzinfo=None) if otp.expires_at.tzinfo else otp.expires_at
        if expires_time < current_time:
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
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}",
        )


@router.post("/signup/resend-otp", response_model=schemas.ResendOTPResponse)
def resend_signup_otp(body: schemas.ResendOTPRequest, db: Session = Depends(get_db)):
    """
    Resend signup OTP for users who already signed up but haven't verified.
    Only works if the account is not yet activated.
    """
    user = db.query(models.User).filter(models.User.email == body.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with this email",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is already activated. Please login instead.",
        )

    # Mark any existing unused signup OTPs as used (to prevent clutter)
    existing_otps = (
        db.query(models.OTPCode)
        .filter(
            models.OTPCode.user_id == user.id,
            models.OTPCode.purpose == "signup",
            models.OTPCode.is_used == False,
        )
        .all()
    )
    for old_otp in existing_otps:
        old_otp.is_used = True
        db.add(old_otp)

    # Generate new OTP
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

    # Send new OTP to email
    subject = "Your New Signup OTP Code"
    body_text = f"Hello {user.name},\n\nYour new signup OTP code is: {otp_code}\n\nIt will expire in 10 minutes."
    send_email(user.email, subject, body_text)

    return schemas.ResendOTPResponse(
        otp_id=otp.id,
        detail="New signup OTP sent to your email",
    )


# -------- LOGIN (Simple Email/Password) --------

@router.post("/login", response_model=schemas.Token)
def login(
    body: schemas.UserLogin,
    db: Session = Depends(get_db),
):
    """
    Simple email/password login. Returns JWT access token immediately.
    No OTP required for login - OTP is only used for email verification during signup.
    """
    user = db.query(models.User).filter(models.User.email == body.email).first()

    if not user or not security.verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not activated. Please verify your email with the OTP sent during signup.",
        )

    access_token = security.create_access_token(data={"sub": str(user.id)})

    return {"access_token": access_token, "token_type": "bearer"}
