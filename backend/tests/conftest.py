"""Shared test fixtures."""
import sqlite3
import uuid
import pytest

from app.config import SCHEMA_PATH


@pytest.fixture
def conn(tmp_path):
    """A fresh in-file SQLite database with the full schema applied."""
    database = tmp_path / "test.db"
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        connection.executescript(f.read())
    yield connection
    connection.close()


@pytest.fixture
def user_id(conn):
    """Insert a minimal user row and return its id.

    user_keys has a foreign key to users, so key tests need a real user.
    """
    uid = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO users
           (user_id, username_idx, username_enc, email_idx, email_enc,
            password_hash, password_salt, kdf_iterations, role,
            key_version, hmac_tag, created_at)
           VALUES (?, 'idx1', 'enc1', 'idx2', 'enc2',
                   'hash', 'salt', 1000, 'OWNER', 1, 'tag', '2026-01-01')""",
        (uid,),
    )
    conn.commit()
    return uid