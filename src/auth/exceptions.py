"""Auth-domain exceptions. Mapped to HTTP responses at the router layer."""


class EmailConflictError(Exception):
    """Raised when registering with an email that already exists."""


class EmailDeliveryError(Exception):
    """Raised when an outbound email (verification, reset) fails to send."""


class InvalidPasswordResetTokenError(Exception):
    """Raised for a missing, expired, or already-used password reset token."""


class AccountLockedError(Exception):
    """Raised when an account is locked (e.g. after too many failed logins)."""


class InvalidCredentialsError(Exception):
    """Raised for any login failure; intentionally generic to avoid email enumeration."""


class EmailNotVerifiedError(Exception):
    """Raised when an unverified user attempts a verified-only action."""


class InvalidRefreshTokenError(Exception):
    """Raised when a refresh token is missing, revoked, or expired."""


class GoogleOAuthError(Exception):
    """Raised on Google OAuth failures; carries an HTTP status_code."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
