"""SQLite connection handling."""
import sqlite3
from app.config import DATABASE_PATH, SCHEMA_PATH


def get_connection() -> sqlite3.Connection:
    """Open a connection with row access by column name and FK enforcement."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create all tables from schema.sql. Safe to run on a fresh file."""
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()
    conn = get_connection()
    conn.executescript(schema)
    conn.commit()
    conn.close()