import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)


class Config:
    """12-Factor environment-driven configuration ready for containerization."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "secureshop-dev-secret-key-change-me")
    
    # Default to SQLite in instance/ folder, override via DATABASE_URL (e.g. PostgreSQL in Docker)
    DEFAULT_DB_PATH = INSTANCE_DIR / "secureshop.db"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # Initial store credit for newly registered customers
    DEFAULT_INITIAL_STORE_CREDIT = float(os.environ.get("DEFAULT_INITIAL_STORE_CREDIT", "500.00"))

    # Token & OTP Lifetimes (seconds)
    VERIFICATION_TOKEN_MAX_AGE = int(os.environ.get("VERIFICATION_TOKEN_MAX_AGE", "3600"))
    OTP_EXPIRY_SECONDS = int(os.environ.get("OTP_EXPIRY_SECONDS", "300"))

    # Email / SMTP settings (supports local MailHog/Mailpit or outbox fallback)
    SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "1025"))
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "false").lower() == "true"
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@secureshop.local")
    MAIL_AUTO_FALLBACK_OUTBOX = True
