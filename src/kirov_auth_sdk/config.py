from pydantic import Field
from pydantic_settings import BaseSettings


class AuthConfig(BaseSettings):
    jwt_secret: str = Field(default="change-me-in-production")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)
    jwt_issuer: str = Field(default="kirov-security-labs")
    jwt_audience: str = Field(default="kirov-services")

    model_config = {"env_prefix": "KIROV_AUTH_"}
