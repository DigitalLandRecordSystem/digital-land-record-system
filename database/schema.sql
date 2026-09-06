PRAGMA foreign_keys = ON;

-- ============ USERS ============
CREATE TABLE users (
    user_id         TEXT PRIMARY KEY,
    username_idx    TEXT NOT NULL UNIQUE,   -- blind index: HMAC(username, lookup_key)
    username_enc    TEXT NOT NULL,          -- RSA
    email_idx       TEXT NOT NULL UNIQUE,   -- blind index
    email_enc       TEXT NOT NULL,          -- RSA
    contact_enc     TEXT,                   -- RSA
    password_hash   TEXT NOT NULL,          -- your PBKDF2-style KDF
    password_salt   TEXT NOT NULL,
    kdf_iterations  INTEGER NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('ADMIN','OWNER')),
    key_version     INTEGER NOT NULL,       -- which RSA key encrypted the above
    hmac_tag        TEXT NOT NULL,          -- integrity over the encrypted fields
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);

-- ============ PROFILES ============
CREATE TABLE profiles (
    profile_id      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
    full_name_enc   TEXT,                   -- RSA
    address_enc     TEXT,                   -- RSA
    phone_enc       TEXT,                   -- RSA
    nid_enc         TEXT,                   -- RSA
    key_version     INTEGER NOT NULL,
    hmac_tag        TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- ============ KEY MANAGEMENT ============
CREATE TABLE user_keys (
    key_id          TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    algorithm       TEXT NOT NULL CHECK (algorithm IN ('RSA','ECC')),
    version         INTEGER NOT NULL,
    public_key      TEXT NOT NULL,          -- plaintext is correct; it's public
    private_key_enc TEXT NOT NULL,          -- RSA-wrapped under the server master key
    hmac_tag        TEXT NOT NULL,          -- integrity over the whole key record
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    retired_at      TEXT,
    UNIQUE (user_id, algorithm, version)
);
CREATE INDEX idx_keys_active ON user_keys(user_id, algorithm, is_active);

-- ============ MESSAGING KEYS ============
-- The one key the Key Management Module deliberately does not hold. The
-- private scalar is derived from the user's password on demand and never
-- stored, so a full database compromise -- master key included -- yields
-- no way to read a transfer message.
CREATE TABLE messaging_keys (
    user_id         TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    public_key      TEXT NOT NULL,          -- plaintext is correct; it's public
    salt            TEXT NOT NULL,          -- separate from the password salt
    iterations      INTEGER NOT NULL,
    created_at      TEXT NOT NULL
);

-- ============ SESSIONS ============
CREATE TABLE sessions (
    session_id      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,   -- SHA-256 of the raw token; raw is never stored
    mfa_verified    INTEGER NOT NULL DEFAULT 0,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    revoked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

-- ============ LOGIN OTPS ============
CREATE TABLE login_otps (
    otp_id          TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    code_hmac       TEXT NOT NULL,          -- HMAC of the code; the code itself is never stored
    attempts        INTEGER NOT NULL DEFAULT 0,
    consumed        INTEGER NOT NULL DEFAULT 0,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);
CREATE INDEX idx_otp_session ON login_otps(session_id, consumed);

-- ============ DEEDS ============
CREATE TABLE deeds (
    deed_id         TEXT PRIMARY KEY,
    plot_no_idx     TEXT NOT NULL UNIQUE,   -- blind index for lookup
    plot_no_enc     TEXT NOT NULL,          -- ECC
    district_enc    TEXT NOT NULL,          -- ECC
    area_enc        TEXT NOT NULL,          -- ECC
    content_enc     TEXT NOT NULL,          -- ECC (EC-ElGamal, chunked)
    owner_id        TEXT NOT NULL REFERENCES users(user_id),
    key_version     INTEGER NOT NULL,       -- ECC key version
    hmac_tag        TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_deeds_owner ON deeds(owner_id);

-- ============ TRANSFER REQUESTS ============
CREATE TABLE transfer_requests (
    request_id      TEXT PRIMARY KEY,
    deed_id         TEXT NOT NULL REFERENCES deeds(deed_id) ON DELETE CASCADE,
    from_user_id    TEXT NOT NULL REFERENCES users(user_id),
    to_user_id      TEXT NOT NULL REFERENCES users(user_id),
    status          TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','APPROVED','REJECTED')),
    reason_enc      TEXT,                   -- admin's rejection reason, RSA
    message_to_enc   TEXT,                   -- ECC, under the recipient's messaging key
    message_from_enc TEXT,                   -- ECC, under the sender's own messaging key
    message_hmac     TEXT,                   -- integrity over both ciphertexts
    requested_on    TEXT NOT NULL,
    decided_on      TEXT,
    decided_by      TEXT REFERENCES users(user_id),
    approval_hmac   TEXT,                   -- HMAC over the decision
    key_version     INTEGER NOT NULL
);
CREATE INDEX idx_transfers_status ON transfer_requests(status);

-- ============ AUDIT LOG (hash chain) ============
CREATE TABLE audit_logs (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id        TEXT,
    action          TEXT NOT NULL,
    entity_type     TEXT,
    entity_id       TEXT,
    timestamp       TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,          -- previous row's entry_hash
    entry_hash      TEXT NOT NULL           -- HMAC(prev_hash || this row's fields)
);