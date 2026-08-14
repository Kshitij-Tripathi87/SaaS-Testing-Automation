"""API Key authentication dependency for the Control Plane.

Extracts the API key from the request headers, validates against DB, and
attaches the ApiKey record and its Project to the request state.

Header reconciliation (Phase 3 Track B):
  - `X-API-Key` is the FROZEN contract header (docs/api_contract.md v1).
  - `X-TenantShield-Key` is the legacy header from the Phase 1 control
    plane. It's accepted for backwards compatibility and will be dropped
    in v2. The contract header is checked first; when both are present,
    `X-API-Key` wins.
"""

import hashlib
import secrets
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import get_db
from app.services.api_key_service import ApiKeyService
from app.db.models import ApiKey


def _extract_api_key(request: Request) -> str:
    """Pull the API key from the contract header, then the legacy one."""
    raw_key = request.headers.get("X-API-Key")
    if raw_key:
        return raw_key
    raw_key = request.headers.get("X-TenantShield-Key")
    if raw_key:
        return raw_key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing X-API-Key header",
    )


async def require_api_key(request: Request, db: AsyncSession = Depends(get_db)) -> ApiKey:
    """FastAPI dependency: extract and validate the API key header."""
    raw_key = _extract_api_key(request)
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
