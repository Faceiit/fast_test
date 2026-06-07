from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies import get_current_principal
from app.core.config import settings
from app.core.security import create_access_token
from app.db.dependencies import get_db
from app.schemas.auth import LoginRequest, PrincipalResponse, TokenResponse
from app.services.auth_service import AuthenticatedPrincipal, authenticate_user


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    principal = authenticate_user(
        db=db,
        username=payload.username,
        password=payload.password,
    )

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(
        principal_id=principal.id,
        principal_type=principal.principal_type,
    )

    return TokenResponse(
        access_token=access_token,
        expires_in_minutes=settings.access_token_expire_minutes,
    )


@router.get("/me", response_model=PrincipalResponse)
def get_me(
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> PrincipalResponse:
    return PrincipalResponse(
        id=current_principal.id,
        principal_type=current_principal.principal_type,
        display_name=current_principal.display_name,
        roles=current_principal.roles,
    )
