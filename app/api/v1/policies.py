from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies import get_current_principal
from app.db.dependencies import get_db
from app.schemas.secret import AccessPolicyCreateRequest, AccessPolicyResponse
from app.services.auth_service import AuthenticatedPrincipal
from app.services.secret_service import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    TargetPrincipalNotFoundError,
    grant_secret_access,
)


router = APIRouter(prefix="/policies", tags=["policies"])


@router.post(
    "",
    response_model=AccessPolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_access_policy_endpoint(
    payload: AccessPolicyCreateRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> AccessPolicyResponse:
    try:
        policy = grant_secret_access(
            db=db,
            secret_path=payload.secret_path,
            target_principal_id=payload.principal_id,
            capability=payload.capability,
            current_principal=current_principal,
            request=request,
        )
    except SecretNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )
    except TargetPrincipalNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target principal not found",
        )
    except SecretAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient secret permissions",
        )

    return AccessPolicyResponse(
        id=policy.id,
        principal_id=policy.principal_id,
        secret_id=policy.secret_id,
        capability=policy.capability,
        created_by=policy.created_by,
        created_at=policy.created_at,
    )
