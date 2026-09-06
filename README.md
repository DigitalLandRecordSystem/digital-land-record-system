# Digital Land Record System

A land-record management system built for CSE447, demonstrating public-key
cryptography applied end to end: encrypted storage, two-step authentication,
key management with rotation, integrity verification, role-based access
control, and end-to-end encrypted messaging.

Owners register the deeds they hold and request ownership transfers.
Administrators decide those transfers. Every stored field that matters is
encrypted, every stored record carries an integrity tag, and no symmetric
cipher is used anywhere.

All cryptographic primitives — SHA-256, HMAC, PBKDF2, RSA with OAEP, and
EC-ElGamal over secp256k1 — are implemented from scratch in pure Python.
No cryptography library is used anywhere in the codebase.

**Author:** Maimuna Chowdhury
**Stack:** Python 3.11+, Flask, Jinja2, SQLite

---

## Requirements map

| Requirement | Where it lives |
|---|---|
| Login and registration | `app/services/user_service.py`, `app/services/auth_service.py`, `app/routes/auth_routes.py` |
| User data encrypted before storage, decrypted on retrieval | `app/services/user_service.py` — RSA-OAEP over username, email, contact |
| Passwords hashed and salted | `app/crypto/kdf.py` — PBKDF2 over from-scratch HMAC-SHA256, with a 16-byte random salt |
| Two-step authentication | `app/services/auth_service.py`, `app/services/otp_service.py` — password, then a six-digit code emailed to the registered address |
| Key management module | `app/crypto/key_manager.py` — generation, distribution, wrapped storage, versioning, rotation |
| Records: create, view, edit | `app/services/deed_service.py`, `app/routes/deed_routes.py` |
| Profiles: view, update | `app/services/profile_service.py`, `app/routes/profile_routes.py` |
| All critical data encrypted at rest | `database/schema.sql` — every `_enc` column; only blind indexes, roles and timestamps are plaintext |
| MAC integrity verification | `app/crypto/hmac_service.py`, `app/crypto/integrity.py` — HMAC-SHA256 tags over users, profiles, deeds, key records, transfer decisions and messages |
| Two asymmetric algorithms, different jobs | RSA for account fields, profiles, rejection reasons and private-key wrapping; ECC (EC-ElGamal over secp256k1) for deed content and transfer messages |
| Role-based access control | `app/routes/deps.py` — `login_required`, `admin_required`, plus ownership checks in the services |
| Secure session management | `app/services/session_service.py` — hashed tokens, expiry, MFA flag, rotation at the second-factor boundary |

Nothing symmetric appears anywhere: no AES, no block cipher, no stream cipher.

---

## Cryptographic design

**Two asymmetric algorithms, separate responsibilities.** RSA encrypts user
account fields, profile data and an administrator's rejection reasons, and
wraps every user private key under the server master key. ECC — EC-ElGamal over
secp256k1 — encrypts deed content and transfer messages. Neither algorithm is
used for the other's job.

**RSA with OAEP.** `app/crypto/rsa_service.py` builds keys the usual way
(`n = pq`, `d = e⁻¹ mod φ(n)`, `e = 65537`) and encrypts blockwise, but with
EME-OAEP padding (RFC 8017) built on this project's own SHA-256 and an MGF1
mask function. The padding matters cryptographically, not cosmetically:
unpadded RSA is deterministic, so an attacker holding the database could
encrypt guesses under a stored public key and match ciphertexts, recovering
low-entropy fields such as an email address without ever seeing a private key.
OAEP injects a fresh random seed into every block, so the same plaintext
encrypts differently every time, and it removes the length leak because each
block encodes its own length.

`sympy.randprime` supplies large primes and Python's built-in `pow` does
modular exponentiation and inversion. Both are general-purpose arithmetic, not
an RSA implementation; key construction, padding, chunking, encryption and
decryption are all written here.

**EC-ElGamal, not ECIES.** ECIES was rejected because its payload layer
requires a symmetric cipher, which the project forbids. EC-ElGamal is purely
asymmetric: `C1 = kG`, `C2 = M + kQ`, with plaintext mapped onto curve points
by Koblitz encoding in 30-byte chunks and a fresh ephemeral scalar `k` for
every chunk. Point addition, doubling, double-and-add scalar multiplication and
the square-root shortcut used for point encoding all live in
`app/crypto/ecc_service.py`.

**HMAC, not CBC-MAC.** CBC-MAC needs a block cipher, so HMAC-SHA256 (RFC 2104)
provides every integrity tag. Tags are keyed with `INTEGRITY_KEY`, held in
`.env` and never in the database, and cover users, profiles, deeds, key
records, transfer decisions and messages. Comparison is constant-time. Editing
a row directly in SQLite makes its tag fail on read: deeds and profiles render
a "modified in storage" page instead of their contents, and the deed list
flags the row rather than hiding it.

**Key storage and distribution.** Public keys are stored in plaintext, which is
correct — they are public — but they are still HMAC-tagged, because
substituting one would silently redirect every future encryption for that user
to an attacker's keypair. Every private key is RSA-wrapped under a server
master keypair kept in `database/master_key.json`, outside the database, so a
stolen database alone yields no private key material. `/keys/directory`
publishes the active public keys, which is what distribution looks like in
practice: encrypting a record for another user never touches that user's
secrets.

**Key rotation.** Rotation issues the next version and retires the previous one
rather than deleting it, so records written under the retired key stay
readable. Every encrypted row stores the `key_version` that wrote it, and reads
look up that version rather than the active key. `Re-encrypt my records` then
migrates account fields, profile and deeds forward onto the new key. Rotation
is treated as a security event: every session for that user is revoked, and the
session performing the rotation is re-issued a fresh token.

**Searchable encryption.** Usernames, emails and plot numbers are encrypted,
which makes them unsearchable. Blind indexes — `HMAC(value, BLIND_INDEX_KEY)` —
restore exact-match lookup and uniqueness without storing plaintext or anything
reversible. They survive key rotation, being HMACs under a separate key rather
than ciphertexts.

**Two-step authentication.** Step one verifies the password with a
constant-time comparison and creates a session marked `mfa_verified = 0`, which
grants access to nothing and expires in five minutes. A six-digit code is then
emailed; only `HMAC(code)` is stored, and the code is bound to that one pending
session, single-use, attempt-capped and time-limited. On success the pending
session is *revoked and replaced*, not upgraded, so a token observed before
verification can never become an authenticated session.

**Session security.** Tokens are random, returned to the client once, and
stored only as a SHA-256 hash, so a database compromise cannot be replayed
against a live session. Cookies are `HttpOnly` and `SameSite=Lax`. Sessions
carry an expiry and an explicit MFA flag, and logout revokes rather than
deletes, so the record survives for audit.

**End-to-end encrypted transfer messages.** A transfer request may carry a
short message readable only by its two parties. This is the one key the Key
Management Module deliberately does *not* hold: the messaging private scalar is
re-derived from the user's password with PBKDF2 on demand, under a separate
salt and a domain-separation label, and is never stored in any form. The
message is EC-ElGamal encrypted twice — once under the recipient's messaging
public key, once under the sender's — with a single HMAC over both ciphertexts.
An administrator can see that a request carries a message, and can approve or
reject the transfer, but holds no scalar that decrypts either copy. A four-byte
`LRS1` canary is prepended before encryption, because EC-ElGamal with a wrong
scalar returns plausible bytes rather than raising; the canary is what turns a
wrong password into a clean rejection instead of noise.

---

## Roles

| Capability | Owner | Administrator |
|---|:--:|:--:|
| Register, sign in with the second factor | yes | yes |
| View and update own profile | yes | yes |
| Create a deed | yes | yes |
| View own deeds | yes | yes |
| View every deed in the system | no | yes |
| Edit a deed | owner only | no |
| Request a transfer of an owned deed | yes | no |
| Approve or reject a transfer | no | yes |
| Read a transfer message | only its two parties | no |
| Rotate own keys, re-encrypt own records | yes | yes |

Administrators can read every deed but cannot edit one; editing belongs to the
owner. These checks live in the services, not only in the templates, so a
hand-crafted request cannot bypass them.

---

## Setup

Requires Python 3.11 or newer.

```
cd backend
python -m venv venv
venv\Scripts\activate            # Windows
source venv/bin/activate         # macOS / Linux
pip install -r requirements.txt
```

Activate the virtual environment in every new terminal.

Copy `.env.example` to `.env`. It needs four secrets — `BLIND_INDEX_KEY`,
`FLASK_SECRET_KEY`, `INTEGRITY_KEY` and `OTP_KEY`. Generate each one
separately:

```
python -c "import secrets; print(secrets.token_hex(32))"
```

Each value is 64 hexadecimal characters, written bare — no quotes, no
brackets, no trailing spaces. The application refuses to start if one is
missing or malformed.

For the second factor, set `OTP_TRANSPORT=console` to print codes to the
terminal (no network required), or `OTP_TRANSPORT=smtp` together with
`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` and `SMTP_FROM` to send
real email. With Gmail, `SMTP_PASSWORD` is a 16-character App Password, not the
account password.

Create the database and the server master key:

```
python init_setup.py
```

Promote an account to administrator:

```
python make_admin.py <username>
```

The role is not encrypted — access control has to read it on every request —
but it is covered by the user row's HMAC tag, which is why this script exists.
Changing the role with raw SQL would break that user's integrity check.

**The database does not migrate.** `init_setup.py` leaves an existing database
alone, and there is no migration path. A database created before a schema
change fails with `no such table` or `no such column`. Delete
`database/land_records.db`, re-run `init_setup.py`, and register again — but
keep `master_key.json`, since accounts created under a different master key
become unreadable without it.

## Running

```
cd backend
venv\Scripts\activate
python run.py
```

Then open http://127.0.0.1:5000

## Tests

```
cd backend
venv\Scripts\activate
python -m pytest tests/ -v
```

113 tests covering the primitives, the key manager, and the service layer.
Test vectors are taken from published references: FIPS 180-4 for SHA-256 and
RFC 4231 for HMAC. The suite is service-level and does not render templates.

---

## Project structure

```
backend/
  app/
    crypto/        from-scratch primitives: hashing (SHA-256), hmac_service,
                   kdf (PBKDF2), rsa_service (RSA + OAEP), ecc_service
                   (secp256k1, EC-ElGamal), key_manager, messaging_key,
                   blind_index, integrity, random_gen
    services/      user, auth, session, otp, mailer, deed, profile,
                   transfer, message
    routes/        Flask blueprints (auth, main, deed, profile, transfer,
                   key) and deps.py — per-request connections and the
                   access-control decorators
    database/      connection handling and schema initialisation
    config.py      configuration and secrets, loaded from .env
  tests/           113 tests
  run.py           development entry point
  init_setup.py    creates the database and the server master key
  make_admin.py    promotes a user to administrator
  requirements.txt pinned
database/
  schema.sql       tables, blind indexes, key versions, HMAC tag columns
frontend/
  templates/       Jinja templates
  static/          stylesheet
docs/              project requirements and report
```

The database file and `master_key.json` are created at setup and are not in
version control.

---

## Known limitations

Stated deliberately; each is a considered tradeoff rather than an oversight.

- **1024-bit RSA keys** (`RSA_KEY_BITS`). Below modern deployment standards.
  Keypair generation in pure Python at 2048 bits is too slow for an
  interactive demonstration; the implementation itself is size-agnostic.
- **1000 KDF iterations.** Current guidance recommends far more. A single
  HMAC-SHA256 call in this implementation takes roughly 840µs, so 600,000
  iterations would add about eight minutes to every login.
- **EC-ElGamal ciphertext leaks plaintext length** through its four-byte length
  prefix, and costs 128 bytes of ciphertext per 30 bytes of plaintext. RSA-OAEP
  leaks neither.
- **No CSRF protection on forms.** Outside the required feature set, but a
  genuine gap in a production deployment.
- **Session cookies are not `Secure`**, only because the demo runs over plain
  HTTP.
- **Rotating `BLIND_INDEX_KEY` invalidates every stored blind index**, since
  each is an HMAC under that key. Rotation would require re-indexing every
  affected row from plaintext.
- **Changing a password invalidates that user's existing transfer messages**,
  since the messaging scalar is derived from the password. That is the price of
  never storing it.
- **`sympy` generates primes and `os.urandom` provides randomness.** Neither is
  an encryption algorithm, and writing a PRNG by hand would be strictly less
  secure.
- **The audit-log table exists but is unused.** The hash-chain schema is in
  place; nothing writes to it yet.

---

## Security notes

`.env` and `database/master_key.json` hold key material and are excluded from
version control. Disclosure of either is a key-rotation event. Losing
`master_key.json` makes every stored private key permanently unrecoverable.
