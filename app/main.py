from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.dependencies import get_db


app = FastAPI(
    title=settings.app_name,
    debug=settings.app_debug,
)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "environment": settings.app_env,
    }


@app.get(f"{settings.api_v1_prefix}/health")
def api_health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "api_prefix": settings.api_v1_prefix,
    }


@app.get(f"{settings.api_v1_prefix}/health/db")
def database_health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))

    return {
        "status": "ok",
        "database": "postgresql",
    }