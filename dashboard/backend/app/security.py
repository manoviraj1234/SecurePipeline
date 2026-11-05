"""
Security and authentication utilities for SecurePipeline Backend.
Includes API Key authorization and response sanitization.
"""

from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from .config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> bool:
    """
    Verifies the X-API-Key header.
    If SECUREPIPELINE_API_KEY is not configured, allows requests freely for local development.
    """
    configured_key = settings.API_KEY.strip()
    if not configured_key:
        return True

    if not api_key or api_key.strip() != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key header (X-API-Key).",
        )
    return True


def redact_secret_string(value: Optional[str]) -> str:
    """Sanitizes raw secret strings."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***REDACTED***"
    return f"{value[:2]}***REDACTED***{value[-2:]}"
