class AuthError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TokenExpiredError(AuthError):
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, status_code=401)


class InvalidTokenError(AuthError):
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message, status_code=401)


class InsufficientPermissionsError(AuthError):
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, status_code=403)
