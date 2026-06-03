from fastapi import APIRouter

from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.policies import router as policies_router
from app.api.v1.secrets import router as secrets_router
from app.api.v1.service_accounts import router as service_accounts_router


api_router = APIRouter()

api_router.include_router(auth_router)
api_router.include_router(service_accounts_router)
api_router.include_router(secrets_router)
api_router.include_router(policies_router)
api_router.include_router(audit_router)