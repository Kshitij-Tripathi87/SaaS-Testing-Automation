"""API Key authentication dependency for the Control Plane.

Extracts X-TenantShield-Key header, validates against DB, and attaches
the ApiKey record and its Project to the request state.
"""

import hashlib
import secrets
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.services.api_key_service import ApiKeyService
from app.db.models import ApiKey


async def require_api_key(request: Request, db: AsyncSession = Depends(get_db)) -> ApiKey:
    """FastAPI dependency: extract and validate the X-TenantShield-Key header."""
    raw_key = request.headers.get("X-TenantShield-Key")
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-TenantShield-Key header",
        )
    service = ApiKeyService(db)
    record = await service.validate_key(raw_key)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )
    request.state.api_key = record
    return record


async def require_scope(scope: str):
    """FastAPI dependency factory: enforce a specific API key scope."""
    async def _check(api_key: ApiKey = Depends(require_api_key)) -> ApiKey:
        scopes = api_key.scopes if isinstance(api_key.scopes, list) else [api_key.scopes]
        if scope not in scopes and "admin" not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key lacks required scope: {scope}",
            )
        return api_key
    return _check
