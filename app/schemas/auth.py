import uuid

from pydantic import BaseModel, Field


class LoginRequest(BaseModel): # Применяется на эндпоинте `/login`, когда пользователь пытается войти.
    username: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel): # что возвращается пользователю, если его логин и пароль совпали
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class PrincipalResponse(BaseModel): # Используется для эндпоинтов вроде `/me`
    id: uuid.UUID
    principal_type: str
    display_name: str
    roles: list[str]