import re


def validate_password_strength(val: str) -> str:
    """Enforce length and character-class rules; return val unchanged on success."""
    # bcrypt truncates above 72 bytes; reject rather than silently truncate.
    if len(val.encode("utf-8")) > 72:
        raise ValueError("Password must be at most 72 bytes long")
    if len(val) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", val):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", val):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", val):
        raise ValueError("Password must contain at least one number")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", val):
        raise ValueError("Password must contain at least one special character")
    return val


def normalize_email(val: str) -> str:
    """Lowercase and strip whitespace for consistent storage and lookup."""
    return val.strip().lower()
