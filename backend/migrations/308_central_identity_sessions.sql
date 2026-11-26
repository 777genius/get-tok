-- Central ownership preserves local user identifiers and financial records.
-- The sticky user fence also rejects legacy human authentication when its
-- external binding is unavailable. Sessions and login intents have finite
-- absolute lifetimes; status refresh cannot extend either lifetime.
ALTER TABLE users ADD COLUMN central_managed boolean NOT NULL DEFAULT false;

CREATE TABLE central_identity_bindings (
    local_user_id bigint PRIMARY KEY REFERENCES users(id),
    authority_incarnation text NOT NULL,
    account_id text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    status_evidence jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (authority_incarnation, account_id),
    UNIQUE (issuer, subject),
    CHECK (length(authority_incarnation) BETWEEN 1 AND 1024),
    CHECK (length(account_id) BETWEEN 1 AND 1024),
    CHECK (length(issuer) BETWEEN 1 AND 2048),
    CHECK (length(subject) BETWEEN 1 AND 1024),
    CHECK (jsonb_typeof(status_evidence) = 'object')
);

CREATE TABLE central_identity_sessions (
    token_hash text PRIMARY KEY CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    local_user_id bigint NOT NULL REFERENCES central_identity_bindings(local_user_id),
    session_evidence jsonb NOT NULL CHECK (jsonb_typeof(session_evidence) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX central_identity_sessions_user_idx ON central_identity_sessions(local_user_id);
CREATE INDEX central_identity_sessions_expiry_idx ON central_identity_sessions(expires_at);

CREATE TABLE central_identity_login_transactions (
    state_hash text PRIMARY KEY CHECK (state_hash ~ '^[a-f0-9]{64}$'),
    browser_hash text NOT NULL CHECK (browser_hash ~ '^[a-f0-9]{64}$'),
    encrypted_intent text NOT NULL CHECK (length(encrypted_intent) BETWEEN 1 AND 32768),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);
CREATE INDEX central_identity_login_expiry_idx ON central_identity_login_transactions(expires_at);
