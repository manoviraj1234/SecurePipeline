"""
Configuration settings for SecurePipeline Backend.
Environment-driven configuration for local development and CI testing.
"""

import os
from typing import List


class Settings:
    PROJECT_NAME: str = "SecurePipeline API"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # SQLite Database URL
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./securepipeline.db")

    # Optional API Key for report ingestion (open for dev if empty)
    API_KEY: str = os.getenv("SECUREPIPELINE_API_KEY", "")

    # CORS origins: strictly whitelist local frontend ports
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


settings = Settings()
