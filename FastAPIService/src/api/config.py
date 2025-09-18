"""
Configuration helpers for the FastAPI service.

This module centralizes environment variable names and default handling.
Do not store secrets in code; use environment variables or secrets management.
"""

from pydantic import BaseModel, Field
import os


class Config(BaseModel):
    """Central configuration model for use by other modules."""
    ENV: str = Field(default=os.getenv("ENV", "development"))
    DEBUG: bool = Field(default=os.getenv("DEBUG", "false").lower() == "true")
    SERVICE_NAME: str = Field(default=os.getenv("SERVICE_NAME", "fastapi-service"))
    DJANGO_SERVICE_URL: str = Field(default=os.getenv("DJANGO_SERVICE_URL", "http://django-service:8000"))
    DATABASE_URL: str = Field(default=os.getenv("DATABASE_URL", "postgresql://user:pass@postgres:5432/dbname"))
    FASTAPI_JWT_SECRET: str = Field(default=os.getenv("FASTAPI_JWT_SECRET", ""))
    FASTAPI_JWT_ALG: str = Field(default=os.getenv("FASTAPI_JWT_ALG", "HS256"))


config = Config()
