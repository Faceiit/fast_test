from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from sqlalchemy.orm import Session

from app.api.v1.dependencies import get_current_principal, require_roles
from app.db.dependencies import get_db
from app.repositories.secrets import list_accessible_secrets
from app.schemas.secret import (
    SECRET_PATH_PATTERN,
    SecretCreateRequest,
    SecretMetadataResponse,
    SecretRotateRequest,
    SecretValueResponse,
)
from app.services.auth_service import AuthenticatedPrincipal
from app.services.secret_service import (
    SecretAccessDeniedError,
    SecretAlreadyExistsError,
    SecretDecryptionFailedError,
    SecretExpiredError,
    SecretNotFoundError,
    create_secret,
    delete_secret,
    read_secret_value,
    rotate_secret_value,
)


router = APIRouter(prefix="/secrets", tags=["secrets"])


SecretPathParam = Annotated[
    str,
    Path(
        min_length=3,
        max_length=512,
        pattern=SECRET_PATH_PATTERN,
    ),
]


def to_secret_metadata_response(secret) -> SecretMetadataResponse:
    return SecretMetadataResponse(
        id=secret.id,
        path=secret.path,
        description=secret.description,
        owner_principal_id=secret.owner_principal_id,
        current_version=secret.current_version,
        created_at=secret.created_at,
        updated_at=secret.updated_at,
    )


@router.post(
    "",
    response_model=SecretMetadataResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_secret_endpoint(
    payload: SecretCreateRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_roles("admin", "developer")),
    ],
) -> SecretMetadataResponse:
    try:
        secret = create_secret(
            db=db,
            path=payload.path,
            value=payload.value,
            description=payload.description,
            expires_at=payload.expires_at,
            current_principal=current_principal,
            request=request,
        )
    except SecretAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Secret already exists",
        )

    return to_secret_metadata_response(secret)


@router.get("", response_model=list[SecretMetadataResponse])
def list_secrets_endpoint(
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> list[SecretMetadataResponse]:
    can_see_all_metadata = bool(
        {"admin", "auditor"}.intersection(current_principal.roles)
    )

    secrets = list_accessible_secrets(
        db=db,
        principal_id=current_principal.id,
        can_see_all_metadata=can_see_all_metadata,
    )

    return [to_secret_metadata_response(secret) for secret in secrets]


@router.post(
    "/{secret_path:path}/versions",
    response_model=SecretMetadataResponse,
)
def rotate_secret_endpoint(
    secret_path: SecretPathParam,
    payload: SecretRotateRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> SecretMetadataResponse:
    try:
        secret = rotate_secret_value(
            db=db,
            path=secret_path,
            value=payload.value,
            expires_at=payload.expires_at,
            current_principal=current_principal,
            request=request,
        )
    except SecretNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )
    except SecretAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient secret permissions",
        )

    return to_secret_metadata_response(secret)


@router.get("/{secret_path:path}", response_model=SecretValueResponse)
def read_secret_endpoint(
    secret_path: SecretPathParam,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> SecretValueResponse:
    try:
        secret, secret_version, plaintext = read_secret_value(
            db=db,
            path=secret_path,
            current_principal=current_principal,
            request=request,
        )
    except SecretNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )
    except SecretAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient secret permissions",
        )
    except SecretExpiredError:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Secret version has expired",
        )
    except SecretDecryptionFailedError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Secret cannot be decrypted",
        )

    return SecretValueResponse(
        id=secret.id,
        path=secret.path,
        description=secret.description,
        current_version=secret.current_version,
        value=plaintext,
        expires_at=secret_version.expires_at,
    )


@router.delete(
    "/{secret_path:path}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_secret_endpoint(
    secret_path: SecretPathParam,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_principal: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> Response:
    try:
        delete_secret(
            db=db,
            path=secret_path,
            current_principal=current_principal,
            request=request,
        )
    except SecretNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )
    except SecretAccessDeniedError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient secret permissions",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)