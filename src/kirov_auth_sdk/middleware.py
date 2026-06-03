from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from kirov_auth_sdk.exceptions import InsufficientPermissionsError, InvalidTokenError, TokenExpiredError
from kirov_auth_sdk.tokens import TokenManager

_security_scheme = HTTPBearer(auto_error=False)


class AuthMiddleware:
    def __init__(
        self,
        token_manager: Optional[TokenManager] = None,
        exclude_paths: Optional[list[str]] = None,
    ):
        self.token_manager = token_manager or TokenManager()
        self.exclude_paths = set(exclude_paths or ["/docs", "/openapi.json", "/health"])

    async def __call__(self, request: Request, call_next: Callable):
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ")
            try:
                payload = self.token_manager.decode_token(token)
                request.state.user = payload
            except (InvalidTokenError, TokenExpiredError):
                request.state.user = None
        else:
            request.state.user = None

        return await call_next(request)


async def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        mgr = TokenManager()
        payload = mgr.decode_token(credentials.credentials)
        return payload
    except InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except TokenExpiredError as e:
        raise HTTPException(status_code=401, detail=str(e))


def require_role(role: str):
    async def _dependency(user: dict = Depends(require_auth)):
        if user.get("role") != role:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role}' required",
            )
        return user

    return _dependency


def require_permission(permission: str):
    async def _dependency(user: dict = Depends(require_auth)):
        perms = user.get("permissions", [])
        if permission not in perms:
            raise HTTPException(
                status_code=403,
                detail=f"Permission '{permission}' required",
            )
        return user

    return _dependency
