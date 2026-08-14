"""Tenant Shield Control Plane — FastAPI application factory."""

from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.api.v1.health import router as health_router
from app.api.v1.runs import router as runs_router
from app.api.v1.keys import router as keys_router
from app.api.v1.artifacts import router as artifacts_router
from app.api.v1.auth import router as auth_router
from app.db.database import init_db
from app.db.queue import run_queue
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables (dev mode) + connect queue
    await init_db()
    if settings.redis_url:
        run_queue.connect_redis(settings.redis_url)
    yield
    # Shutdown: cleanup (Redis connection close, etc.)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Tenant Shield Control Plane",
        version="0.2.0",
        description="The orchestration API for the Tenant Shield multi-tenant testing platform.",
        lifespan=lifespan,
    )
    app.include_router(health_router, prefix="/v1", tags=["health"])
    app.include_router(runs_router, prefix="/v1", tags=["runs"])
    app.include_router(keys_router, prefix="/v1", tags=["keys"])
    app.include_router(artifacts_router, prefix="/v1", tags=["artifacts"])
    app.include_router(auth_router, prefix="/v1", tags=["auth"])

    @app.get("/")
    async def root():
        return {"service": "tenant-shield-control-plane", "version": "0.2.0", "docs": "/docs"}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
