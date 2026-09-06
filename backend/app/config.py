"""Application configuration, loaded from .env."""
import os
from pathlib import Path
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

load_dotenv(BACKEND_DIR / ".env")


def _path(env_name: str, default: str) -> Path:
    """Resolve a path from .env relative to the backend directory."""
    return (BACKEND_DIR / os.getenv(env_name, default)).resolve()


def _secret(name: str) -> bytes:
    """Load a 64-hex-character secret, failing loudly if absent or malformed."""
    value = os.getenv(name, "")
    if len(value) != 64:
        raise RuntimeError(
            f"{name} missing or malformed in .env "
            f"(expected 64 hex characters, got {len(value)})"
        )
    try:
        return bytes.fromhex(value)
    except ValueError:
        raise RuntimeError(f"{name} in .env is not valid hexadecimal") from None


# ---- paths ----
DATABASE_PATH   = _path("DATABASE_PATH",   "../database/land_records.db")
SCHEMA_PATH     = _path("SCHEMA_PATH",     "../database/schema.sql")
MASTER_KEY_PATH = _path("MASTER_KEY_PATH", "../database/master_key.json")

# ---- crypto settings ----
KDF_ITERATIONS           = int(os.getenv("KDF_ITERATIONS", "1000"))
RSA_KEY_BITS             = int(os.getenv("RSA_KEY_BITS", "1024"))
SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", "30"))

# ---- secrets (never committed; see .env.example) ----
BLIND_INDEX_KEY  = _secret("BLIND_INDEX_KEY")
INTEGRITY_KEY    = _secret("INTEGRITY_KEY")
FLASK_SECRET_KEY = _secret("FLASK_SECRET_KEY")
OTP_KEY          = _secret("OTP_KEY")

# ---- email one-time passwords ----
OTP_TTL_SECONDS  = int(os.getenv("OTP_TTL_SECONDS", "300"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "3"))
OTP_TRANSPORT    = os.getenv("OTP_TRANSPORT", "console").lower()

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "") or SMTP_USER