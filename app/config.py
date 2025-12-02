# app/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "FastAPI JWT Auth"
    DATABASE_URL: str = "postgresql+psycopg2://postgres:postgres@localhost:5432/mydb"
    JWT_SECRET_KEY: str = "change-this-in-env"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    class Config:
        env_file = ".env"


settings = Settings()
