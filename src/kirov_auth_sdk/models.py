from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    sub: str
    role: str
    permissions: list[str]
    exp: int
    jti: str


class UserInfo(BaseModel):
    id: str
    username: str
    email: str
    role: str
