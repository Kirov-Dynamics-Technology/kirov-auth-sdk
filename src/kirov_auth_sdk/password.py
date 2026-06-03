import re

from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordManager:
    @staticmethod
    def hash_password(password: str) -> str:
        return _pwd_context.hash(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        return _pwd_context.verify(password, hashed)

    @staticmethod
    def validate_password_strength(password: str) -> dict:
        checks = {
            "length": len(password) >= 12,
            "uppercase": bool(re.search(r"[A-Z]", password)),
            "lowercase": bool(re.search(r"[a-z]", password)),
            "digit": bool(re.search(r"\d", password)),
            "special_char": bool(re.search(r"[!@#$%^&*(),.?:{}|<>]", password)),
        }
        passed = sum(1 for v in checks.values() if v)
        total = len(checks)
        return {
            "valid": all(checks.values()),
            "checks": checks,
            "score": int((passed / total) * 100),
        }
