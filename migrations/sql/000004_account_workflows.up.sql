CREATE TABLE oauth_states (
 token_hash TEXT PRIMARY KEY,
 provider TEXT NOT NULL CHECK(provider IN ('google','vk')),
 redirect_uri TEXT NOT NULL,
 binding_hash TEXT NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX oauth_states_expiration ON oauth_states(expires_at);
CREATE TABLE email_bindings (
 token_hash TEXT PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('verify','change')),
 stage TEXT NOT NULL CHECK(stage IN ('verify','old','new')),
 old_email TEXT NOT NULL,
 email TEXT NOT NULL,
 password_hash BYTEA,
 expires_at TIMESTAMPTZ NOT NULL,
 UNIQUE(user_id,purpose)
);
CREATE INDEX email_bindings_expiration ON email_bindings(expires_at);

CREATE TABLE email_deliveries (
 id BIGSERIAL PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
 email TEXT NOT NULL,
 token TEXT NOT NULL,
 link_pattern TEXT NOT NULL,
 purpose TEXT NOT NULL,
 stage TEXT NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 next_attempt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX email_deliveries_pending ON email_deliveries(next_attempt);

CREATE TABLE reauthentication_proofs(
 token_hash TEXT PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
 expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX reauthentication_proofs_expiration ON reauthentication_proofs(expires_at);
