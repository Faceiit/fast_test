from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    app_name: str = "Secret Management Service"
    app_env: str = "dev"
    app_debug: bool = True
    docs_enabled: bool = True

    api_v1_prefix: str = "/api/v1"

    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "secret_manager"
    postgres_user: str = "secret_manager"
    postgres_password: str = "change_me"

    jwt_secret_key: str = "change_me_generate_real_value"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    api_key_pepper: str = "change_me_generate_real_value"

    log_level: str = "INFO"

    master_key_file: str = "/run/secrets/sms_master_key"
    encryption_key_version: str = "local-v1"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def database_url(self) -> str:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        ).render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
