from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies import require_roles
from app.db.dependencies import get_db
from app.schemas.service_account import (
    ServiceAccountCreateRequest,
    ServiceAccountCreateResponse,
)
from app.services.auth_service import AuthenticatedPrincipal
from app.services.service_account_service import (
    ServiceAccountAlreadyExistsError,
    create_service_account,
)


router = APIRouter(prefix="/service-accounts", tags=["service accounts"])


@router.post("", response_model=ServiceAccountCreateResponse)
def create_service_account_endpoint(
    payload: ServiceAccountCreateRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_roles("admin")),
    ],
) -> ServiceAccountCreateResponse:
    try:
        service_account, raw_api_key = create_service_account(
            db=db,
            name=payload.name,
            expires_at=payload.expires_at,
            current_principal=current_principal,
            request=request,
        )
    except ServiceAccountAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Service account already exists or API key prefix collided",
        )

    return ServiceAccountCreateResponse(
        principal_id=service_account.principal_id,
        name=service_account.name,
        api_key=raw_api_key,
        api_key_prefix=service_account.api_key_prefix,
    )
