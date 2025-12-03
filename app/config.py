# app/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "FastAPI JWT Auth"
    DATABASE_URL: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/mydb"
    JWT_SECRET_KEY: str = "change-this-in-env"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30


        # EMAIL (Gmail SMTP example)
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "jahidul.cse.gub@gmail.com"
    SMTP_PASSWORD: str = "your_app_password"  # use Gmail App Password, NOT your real password
    EMAIL_FROM: str = "no-reply@ijahidul.com"  # or use same as SMTP_USER


    class Config:
        env_file = ".env"


settings = Settings()
