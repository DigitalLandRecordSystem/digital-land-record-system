"""One-time setup: create the database and the server master keypair.

The master keypair encrypts users' private keys before they are stored.
Its own private key is kept in a file outside the database, so that a
database compromise alone does not expose any user's private key.
"""
import json
import os

from app.config import MASTER_KEY_PATH, DATABASE_PATH, RSA_KEY_BITS
from app.database.db import init_db
from app.crypto.rsa_service import generate_keypair


def create_master_key():
    if MASTER_KEY_PATH.exists():
        print(f"Master key already exists at {MASTER_KEY_PATH}, leaving it alone.")
        return

    print(f"Generating {RSA_KEY_BITS}-bit master keypair...")
    public, private = generate_keypair(RSA_KEY_BITS)

    MASTER_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MASTER_KEY_PATH, "w", encoding="utf-8") as f:
        json.dump({"public": public, "private": private}, f, indent=2)
    print(f"Master key written to {MASTER_KEY_PATH}")


def main():
    if DATABASE_PATH.exists():
        print(f"Database already exists at {DATABASE_PATH}, leaving it alone.")
    else:
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        init_db()
        print(f"Database created at {DATABASE_PATH}")
    create_master_key()


if __name__ == "__main__":
    main()