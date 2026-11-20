import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)


class Config:
    """12-Factor environment-driven configuration hardened against OWASP & Lab Threats."""
    # Strong secret key (use environment variable in Docker/production)
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # Default to SQLite in instance/ folder, override via DATABASE_URL (e.g. PostgreSQL in Docker)
    DEFAULT_DB_PATH = INSTANCE_DIR / "secureshop.db"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Hardened Session & Cookie Flags (MitM / XSS / CSRF Defense)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_SECONDS", "28800"))  # 8 hours

    # Request size limit (prevents oversized payload DoS / crash probing)
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

    # Initial store credit for newly registered customers
    DEFAULT_INITIAL_STORE_CREDIT = float(os.environ.get("DEFAULT_INITIAL_STORE_CREDIT", "500.00"))

    # Token & OTP Lifetimes (seconds)
    VERIFICATION_TOKEN_MAX_AGE = int(os.environ.get("VERIFICATION_TOKEN_MAX_AGE", "3600"))
    OTP_EXPIRY_SECONDS = int(os.environ.get("OTP_EXPIRY_SECONDS", "300"))
    PASSKEY_CHALLENGE_EXPIRY_SECONDS = int(os.environ.get("PASSKEY_CHALLENGE_EXPIRY_SECONDS", "120"))

    # Brute-Force & Rate Limiting Controls
    MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_SECONDS = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))
    MAX_OTP_ATTEMPTS = int(os.environ.get("MAX_OTP_ATTEMPTS", "5"))
    OTP_LOCKOUT_SECONDS = int(os.environ.get("OTP_LOCKOUT_SECONDS", "300"))
    GLOBAL_RATE_LIMIT_PER_MIN = int(os.environ.get("GLOBAL_RATE_LIMIT_PER_MIN", "120"))

    # Business Rule Hard Caps (SR-2)
    MAX_COUPONS_PER_ORDER = int(os.environ.get("MAX_COUPONS_PER_ORDER", "2"))
    MAX_CUMULATIVE_DISCOUNT_PERCENT = int(os.environ.get("MAX_CUMULATIVE_DISCOUNT_PERCENT", "50"))
    MAX_CART_QUANTITY_PER_ITEM = int(os.environ.get("MAX_CART_QUANTITY_PER_ITEM", "99"))

    # Behavioral & Context-Aware Login Defense (Lab 4 & Lab 5)
    ALLOWED_REGIONS = [r.strip().upper() for r in os.environ.get("ALLOWED_REGIONS", "US-EAST,US-WEST,EU-WEST,LOCAL").split(",") if r.strip()]
    ALLOWED_LOGIN_HOUR_START = int(os.environ.get("ALLOWED_LOGIN_HOUR_START", "0"))
    ALLOWED_LOGIN_HOUR_END = int(os.environ.get("ALLOWED_LOGIN_HOUR_END", "23"))
    ENFORCE_BUSINESS_HOURS = os.environ.get("ENFORCE_BUSINESS_HOURS", "false").lower() == "true"

    # Email / SMTP settings (supports local MailHog/Mailpit or outbox fallback)
    SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "false").lower() == "true"
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@secureshop.local")
    MAIL_AUTO_FALLBACK_OUTBOX = True
