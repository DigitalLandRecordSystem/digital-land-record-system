# Digital Land Record System

A land-record management system built for CSE447, demonstrating public-key
cryptography applied end to end: encrypted storage, two-step authentication,
key management, integrity verification, and role-based access control.

All cryptographic primitives are implemented from scratch in pure Python.
No cryptography library is used anywhere in the codebase.

**Author:** Maimuna Chowdhury

---

## Requirements map

| Requirement | Where it lives |
|---|---|
| Login and registration | `app/services/user_service.py`, `app/services/auth_service.py`, `app/web/auth_routes.py` |
| User data encrypted at rest | `app/services/user_service.py` — RSA over username, email, contact, TOTP secret |
| Passwords hashed and salted | `app/crypto/kdf.py` — PBKDF2-style derivation over from-scratch HMAC-SHA256 |
| Two-step authentication | `app/services/auth_service.py` — password, then time-based one-time code |
| Key management module | `app/crypto/key_manager.py` — generation, storage, versioning, rotation |
| Posts: create, view, edit | `app/services/deed_service.py`, `app/web/deed_routes.py` |
| Profiles: view, update | `app/services/profile_service.py`, `app/web/profile_routes.py` |
| MAC integrity verification | `app/crypto/hmac_service.py`, `app/crypto/integrity.py` |
| Two asymmetric algorithms | RSA for user and profile data; EC-ElGamal over secp256k1 for deed content |
| Role-based access control | `app/web/deps.py` — `login_required`, `admin_required` |
| Secure session management | `app/services/session_service.py` — hashed tokens, expiry, MFA flag, rotation |

---

## Cryptographic design

**Two asymmetric algorithms, separate responsibilities.** RSA encrypts user
account fields and profile data, and also wraps each user's private keys under
the server master key. EC-ElGamal over secp256k1 encrypts deed content. Neither
algorithm is used for the other's job.

**No symmetric encryption anywhere.** ECIES was rejected because its payload
layer requires a symmetric cipher. EC-ElGamal (`C1 = kG`, `C2 = M + kQ`) is
purely asymmetric: plaintext is mapped to curve points by Koblitz encoding in
30-byte chunks, with a fresh ephemeral scalar per chunk. CBC-MAC was rejected
for the same reason — it requires a block cipher — so HMAC-SHA256 provides all
integrity tags.

**Key storage.** Public keys are stored in plaintext, which is correct. Every
private key is RSA-wrapped under a server master keypair held in
`database/master_key.json`, outside the database. A stolen database alone
yields no private key material.

**Searchable encryption.** Usernames, emails and plot numbers are stored
encrypted, which makes them unsearchable. Blind indexes —
`HMAC(value, BLIND_INDEX_KEY)` — restore exact-match lookup without storing
plaintext or a reversible transformation.

**Session security.** A session token is random and returned to the client once;
only its SHA-256 hash is stored, so a database compromise cannot be replayed
against a live session. Passing the password check creates a session marked
unverified, which grants access to nothing. On successful second-factor
verification that session is revoked and a fresh token issued, so a token
observed before verification can never become an authenticated session.

---

## Setup

Requires Python 3.11 or newer.

cd backend
python -m venv venv
venv\Scripts\activate # Windows
source venv/bin/activate # macOS / Linux
pip install -r requirements.txt

Copy `.env.example` to `.env` and fill in the three secrets. Generate each one
separately:

Generate secret keys: (3)
python -c "import secrets; print(secrets.token_hex(32))"
output: Each value is 64 hexadecimal characters, written bare — no quotes, no brackets,
no trailing spaces.

Create the database and server master key:
python init_setup.py


## Running
cd backend
venv\Scripts\activate
python run.py

Then open http://127.0.0.1:5000

## Tests
cd backend
venv\Scripts\activate
python -m pytest tests/ -v

Test vectors are taken from published references: FIPS 180-4 for SHA-256 and
RFC 4231 for HMAC.

---

## Project structure
backend/
app/
crypto/ from-scratch primitives: SHA-256, HMAC, KDF, RSA, ECC,
key manager, TOTP, blind index, integrity
services/ business logic: users, auth, sessions, deeds, profiles
database/ connection handling
web/ Flask blueprints, access-control decorators
templates/ Jinja templates
static/ stylesheet
tests/
run.py development entry point
init_setup.py creates the database and master key
database/
schema.sql


---

## Known limitations

Stated deliberately; each is a considered tradeoff rather than an oversight.

- **Textbook RSA without OAEP padding.** Encryption is therefore deterministic:
  identical plaintexts produce identical ciphertexts, leaking equality between
  fields. Chosen to match the construction studied in the course.
- **1024-bit RSA keys.** Below modern deployment standards. Chosen because
  keypair generation in pure Python at 2048 bits is prohibitively slow for an
  interactive demonstration.
- **1000 KDF iterations.** Current guidance recommends far more. Measured on
  this implementation, a single HMAC-SHA256 call takes roughly 840µs, so
  600,000 iterations would add about eight minutes to every login.
- **One-time codes use HMAC-SHA256 rather than SHA-1**, so they do not pair
  with standard authenticator applications. The current code is displayed in
  the interface for demonstration.
- **No CSRF protection on forms.** Outside the scope of the required feature
  set, but a genuine gap in a production deployment.
- **Rotating `BLIND_INDEX_KEY` invalidates every stored blind index**, since
  each is an HMAC under that key. Rotation requires re-indexing every affected
  row from plaintext.

---

## Security notes

`.env` and `database/master_key.json` hold key material and are excluded from
version control. Disclosure of either is a key-rotation event.