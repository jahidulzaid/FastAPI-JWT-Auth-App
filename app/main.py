# app/main.py
from fastapi import FastAPI

from .config import settings
from .database import Base, engine
from .routers import auth, users

# Dev only: in production, use Alembic migrations instead
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

# Include routers
app.include_router(auth.router)
# app.include_router(users.router)



