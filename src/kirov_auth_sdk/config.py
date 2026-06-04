from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class AuthConfig(BaseSettings):
    jwt_secret: str = Field(
        default="",
        description="JWT signing secret. Must be set in production via env var KIROV_AUTH_JWT_SECRET.",
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=15)
    refresh_token_expire_days: int = Field(default=7)
    jwt_issuer: str = Field(default="kirov-security-labs")
    jwt_audience: str = Field(default="kirov-services")

    model_config = {"env_prefix": "KIROV_AUTH_", "env_file": ".env"}

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        stripped = v.strip() if v else ""
        if (
            not stripped
            or "placeholder" in stripped.lower()
            or "change" in stripped.lower()
        ):
            raise ValueError(
                "JWT_SECRET must be set and must not be a placeholder. "
                "Set the KIROV_AUTH_JWT_SECRET environment variable or add it to your .env file."
            )
        return stripped
