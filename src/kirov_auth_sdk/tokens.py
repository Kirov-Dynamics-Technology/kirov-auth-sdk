import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from kirov_auth_sdk.config import AuthConfig
from kirov_auth_sdk.exceptions import InvalidTokenError, TokenExpiredError


class TokenManager:
    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self._revoked: set[str] = set()

    def create_access_token(
        self,
        user_id: str,
        role: str,
        permissions: Optional[list[str]] = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        payload = {
            "sub": user_id,
            "role": role,
            "permissions": permissions or [],
            "iat": int(now.timestamp()),
            "exp": int(
                (now + timedelta(minutes=self.config.access_token_expire_minutes)).timestamp()
            ),
            "jti": jti,
            "iss": self.config.jwt_issuer,
            "aud": self.config.jwt_audience,
            "type": "access",
        }
        return jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)

    def create_refresh_token(self, user_id: str) -> str:
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(
                (now + timedelta(days=self.config.refresh_token_expire_days)).timestamp()
            ),
            "jti": jti,
            "iss": self.config.jwt_issuer,
            "aud": self.config.jwt_audience,
            "type": "refresh",
        }
        return jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)

    def decode_token(self, token: str) -> dict:
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
                audience=self.config.jwt_audience,
                issuer=self.config.jwt_issuer,
            )
        except JWTError as e:
            raise InvalidTokenError(str(e))

        if payload.get("jti") in self._revoked:
            raise InvalidTokenError("Token has been revoked")

        return payload

    def refresh_access_token(self, refresh_token: str) -> str:
        payload = self.decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise InvalidTokenError("Not a refresh token")

        user_id = payload["sub"]
        new_payload = jwt.decode(
            refresh_token,
            self.config.jwt_secret,
            algorithms=[self.config.jwt_algorithm],
            audience=self.config.jwt_audience,
            issuer=self.config.jwt_issuer,
            options={"verify_exp": False},
        )
        role = new_payload.get("role", "user")
        permissions = new_payload.get("permissions", [])

        return self.create_access_token(user_id, role, permissions)

    def revoke_token(self, jti: str) -> None:
        self._revoked.add(jti)
