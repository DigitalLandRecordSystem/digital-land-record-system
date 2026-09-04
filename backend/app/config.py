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


DATABASE_PATH   = _path("DATABASE_PATH",   "../database/land_records.db")
SCHEMA_PATH     = _path("SCHEMA_PATH",     "../database/schema.sql")
MASTER_KEY_PATH = _path("MASTER_KEY_PATH", "../database/master_key.json")

KDF_ITERATIONS           = int(os.getenv("KDF_ITERATIONS", "1000"))
RSA_KEY_BITS             = int(os.getenv("RSA_KEY_BITS", "1024"))
SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", "30"))

BLIND_INDEX_KEY  = bytes.fromhex(os.getenv("BLIND_INDEX_KEY", ""))
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "")