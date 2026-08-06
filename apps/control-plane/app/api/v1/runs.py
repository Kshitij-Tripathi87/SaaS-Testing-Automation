"""Run submission, status, completion, and listing endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from tenant_shield_schema import RunSpec, RunStatus
from app.db.database import get_db
from app.db.models import ApiKey, TestRun
from app.services.run_service import RunService
from app.core.security import require_api_key

router = APIRouter(prefix="/runs", tags=["runs"])


class CreateRunResponse(BaseModel):
    run_id: str
    status: RunStatus = RunStatus.QUEUED


class RunStatusResponse(BaseModel):
    run_id: str
    goal: str
    status: RunStatus
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    summary: Optional[dict] = None
    logs: Optional[str] = None


class CompleteRunRequest(BaseModel):
    status: str = "completed"
    error: Optional[str] = None
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    deselected: int = 0
    positive_controls_passed: int = 0
    duration_seconds: float = 0.0


@router.post("", response_model=CreateRunResponse, status_code=202)
async def create_run(spec: RunSpec, api_key: ApiKey = Depends(require_api_key), db: AsyncSession = Depends(get_db)):
    service = RunService(db)
    run = await service.create_run(api_key.project_id, spec.model_dump())
    return CreateRunResponse(run_id=run.id, status=RunStatus.QUEUED)


@router.get("", response_model=list[CreateRunResponse])
async def list_runs(db: AsyncSession = Depends(get_db), limit: int = 20, api_key: ApiKey = Depends(require_api_key)):
    service = RunService(db)
    runs = await service.list_runs(project_id=api_key.project_id, limit=limit)
    return [CreateRunResponse(run_id=r.id, status=RunStatus(r.status)) for r in runs]


@router.get("/{run_id}", response_model=RunStatusResponse)
async def get_run(run_id: str, db: AsyncSession = Depends(get_db)):
    service = RunService(db)
    run = await service.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunStatusResponse(
        run_id=run.id,
        goal=run.goal,
        status=RunStatus(run.status),
        started_at=run.started_at.isoformat() if run.started_at else None,
        finished_at=run.finished_at.isoformat() if run.finished_at else None,
        summary=run.summary_json or None,
        logs=run.logs or None,
    )


@router.post("/{run_id}/complete")
async def complete_run(run_id: str, req: CompleteRunRequest, db: AsyncSession = Depends(get_db)):
    service = RunService(db)
    summary = req.model_dump()
    if req.error:
        await service.fail_run(run_id, req.error)
    else:
        await service.complete_run(run_id, summary)
    return {"run_id": run_id, "status": "completed"}


@router.post("/{run_id}/logs")
async def append_logs(run_id: str, log_line: str = "", db: AsyncSession = Depends(get_db)):
    service = RunService(db)
    await service.append_logs(run_id, log_line)
    return {"run_id": run_id, "ack": True}


@router.post("/{run_id}/cancel")
async def cancel_run(run_id: str, db: AsyncSession = Depends(get_db)):
    service = RunService(db)
    await service.cancel_run(run_id)
    return {"run_id": run_id, "status": "cancelled"}
