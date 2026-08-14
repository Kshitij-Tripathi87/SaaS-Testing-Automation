"""Auth endpoints — frozen contract (docs/api_contract.md v1).

POST /v1/auth/demo-token : demo-only. Returns a fixed, seeded API key for
    the demo account. Real OAuth is on the roadmap, not in this version.

The demo key is a FIXED constant (not random-per-call) so the same key
works across restarts and test runs. It is stored only as a PBKDF2 hash
(SHA-256-family, salted, 100k iterations) — the plaintext key is never
stored or logged, matching the frozen contract's hashing requirement.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import ApiKey, Project, Organization
from app.services.api_key_service import ApiKeyService
from app.core.crypto import hash_api_key

router = APIRouter(prefix="/auth", tags=["auth"])

# Fixed seeded demo key. wfl_ + 32 hex chars per the contract's key shape.
DEMO_RAW_KEY = "wfl_" + "a1b2c3d4e5f67890abcdef1234567890"
DEMO_KEY_LABEL = "demo-token"


@router.post("/demo-token")
async def issue_demo_token(db: AsyncSession = Depends(get_db)):
    """Issue the fixed demo API key (demo-only; no real auth).

    Creates the demo key + default project on first call; returns the same
    raw key every time. The raw key is deterministic so the demo works
    across control-plane restarts.
    """
    service = ApiKeyService(db)

    # Ensure a default project exists (mirrors POST /v1/keys bootstrap).
    project = await db.get(Project, "default")
    if not project:
        org = Organization(name="Default Org")
        db.add(org)
        await db.flush()
        project = Project(id="default", org_id=org.id, name="Default Project")
        db.add(project)
        await db.commit()

    # Return the existing demo key if already seeded.
    stmt = select(ApiKey).where(ApiKey.label == DEMO_KEY_LABEL)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        return {"api_key": DEMO_RAW_KEY}

    record = ApiKey(
        project_id="default",
        key_hash=hash_api_key(DEMO_RAW_KEY),
        label=DEMO_KEY_LABEL,
        scopes=["run_tests", "read_reports", "admin"],
    )
    db.add(record)
    await db.commit()
    return {"api_key": DEMO_RAW_KEY}
