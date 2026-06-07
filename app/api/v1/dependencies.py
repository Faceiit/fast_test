import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.dependencies import get_db
from app.models.identity import PrincipalType
from app.services.auth_service import (
    AuthenticatedPrincipal,
    authenticate_api_key,
    build_authenticated_principal_from_jwt,
)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_principal(
    db: Annotated[Session, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> AuthenticatedPrincipal:
    if authorization is not None and x_api_key is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use either Bearer token or X-API-Key, not both",
        )

    if authorization is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise _unauthorized("Invalid authorization header")

        payload = decode_access_token(token.strip())
        if payload is None:
            raise _unauthorized("Invalid access token")

        try:
            principal_id = uuid.UUID(payload["sub"])
        except (KeyError, ValueError):
            raise _unauthorized("Invalid access token payload")

        token_type = payload.get("type")
        allowed_types = {PrincipalType.USER.value, PrincipalType.SERVICE_ACCOUNT.value}
        if token_type not in allowed_types:
            raise _unauthorized("Invalid access token payload")

        principal = build_authenticated_principal_from_jwt(db, principal_id)
        if principal is None:
            raise _unauthorized("Principal is inactive or does not exist")

        if principal.principal_type != token_type:
            raise _unauthorized("Invalid access token payload")

        return principal

    if x_api_key is not None:
        principal = authenticate_api_key(db, x_api_key)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        return principal

    raise _unauthorized("Authentication required")


def require_roles(
    *allowed_roles: str,
) -> Callable[[AuthenticatedPrincipal], AuthenticatedPrincipal]:
    normalized_allowed_roles = {role.strip().lower() for role in allowed_roles}

    def dependency(
        current_principal: Annotated[
            AuthenticatedPrincipal,
            Depends(get_current_principal),
        ],
    ) -> AuthenticatedPrincipal:
        if not set(current_principal.roles).intersection(normalized_allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_principal

    return dependency
