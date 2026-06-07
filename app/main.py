import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.v1.router import api_router
from app.core.config import settings
from app.db.dependencies import get_db


logger = logging.getLogger(__name__)


def validate_runtime_settings() -> None:
    if settings.jwt_algorithm != "HS256":
        raise RuntimeError("Only HS256 JWT algorithm is supported")

    if settings.postgres_password == "change_me":
        raise RuntimeError("POSTGRES_PASSWORD must be changed")

    if settings.jwt_secret_key == "change_me":
        raise RuntimeError("JWT_SECRET_KEY must be changed")

    if settings.api_key_pepper == "change_me":
        raise RuntimeError("API_KEY_PEPPER must be changed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_settings()
    yield


app = FastAPI(
    title=settings.app_name,
    debug=settings.app_debug,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
    lifespan=lifespan,
)

app.include_router(api_router, prefix=settings.api_v1_prefix)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    request_id = getattr(request.state, "request_id", None)
    logger.exception("Database error", extra={"request_id": request_id})

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database is unavailable", "request_id": request_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.exception("Unhandled application error", extra={"request_id": request_id})

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "request_id": request_id},
    )


@app.get("/health", include_in_schema=False)
@app.get(f"{settings.api_v1_prefix}/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "api_prefix": settings.api_v1_prefix,
    }


@app.get(f"{settings.api_v1_prefix}/health/db")
def database_health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        )

    return {"status": "ok", "database": "postgresql"}
