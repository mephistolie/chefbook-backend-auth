-- Initial schema for an EMPTY auth database. This is not a legacy-data migration.
-- Deliberately no IF NOT EXISTS: incompatible databases must fail, not mix schemas.
-- Execute in a caller-owned transaction (schema.Initialize does this).
CREATE TABLE accounts (
 account_id UUID PRIMARY KEY, email TEXT NOT NULL UNIQUE, email_verification_timestamp TIMESTAMPTZ,
 username TEXT UNIQUE, password_hash TEXT, password_change_timestamp TIMESTAMPTZ,
 blocking_timestamp TIMESTAMPTZ, creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE identities (
 account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE, provider TEXT NOT NULL CHECK(provider IN ('google','vk')),
 subject TEXT NOT NULL CHECK(subject <> ''), creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(account_id,provider), UNIQUE(provider,subject)
);
CREATE TABLE sessions (
 session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
 refresh_token_hash BYTEA NOT NULL UNIQUE, ip INET NOT NULL, user_agent TEXT NOT NULL,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), last_refresh_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
 expiration_timestamp TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_account ON sessions(account_id);
CREATE TABLE authentications (
 authentication_id UUID PRIMARY KEY,
 purpose TEXT NOT NULL CHECK(purpose IN ('signIn','signUp','passwordChange','emailChange','accountDeletion','totpEnrollment','totpRemoval','passkeyEnrollment','passkeyRemoval','backupCodesRotation','identityLink','identityUnlink')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed','failed','cancelled')),
 account_id UUID REFERENCES accounts ON DELETE CASCADE, session_id BIGINT REFERENCES sessions ON DELETE CASCADE,
 flow_token_hash BYTEA NOT NULL UNIQUE, failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0),
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), expiration_timestamp TIMESTAMPTZ NOT NULL,
 completion_timestamp TIMESTAMPTZ, invalidation_timestamp TIMESTAMPTZ,
 confirmation_token_hash BYTEA UNIQUE, confirmation_expiration_timestamp TIMESTAMPTZ,
 CHECK ((confirmation_token_hash IS NULL) = (confirmation_expiration_timestamp IS NULL)),
 CHECK (purpose IN ('signIn','signUp') OR (account_id IS NOT NULL AND session_id IS NOT NULL)),
 CHECK (status <> 'completed' OR (account_id IS NOT NULL AND completion_timestamp IS NOT NULL))
);
CREATE INDEX authentications_session ON authentications(session_id,completion_timestamp DESC);
CREATE INDEX authentications_expiration ON authentications(expiration_timestamp);
CREATE TABLE registrations (
 authentication_id UUID PRIMARY KEY REFERENCES authentications ON DELETE CASCADE,
 email TEXT NOT NULL, password_hash TEXT
);
CREATE TABLE authentication_steps (
 step_id UUID PRIMARY KEY, authentication_id UUID NOT NULL REFERENCES authentications ON DELETE CASCADE,
 type TEXT NOT NULL CHECK(type IN ('registration','passwordSetup','passwordVerification','googleVerification','vkVerification','passkeyVerification','totpVerification','backupCodeVerification','emailVerification')),
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed','failed','cancelled')),
 failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK(failed_attempts >= 0),
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), expiration_timestamp TIMESTAMPTZ NOT NULL,
 completion_timestamp TIMESTAMPTZ, CHECK(status <> 'completed' OR completion_timestamp IS NOT NULL)
);
CREATE INDEX authentication_steps_process ON authentication_steps(authentication_id);
CREATE TABLE email_authentication_steps (
 step_id UUID PRIMARY KEY REFERENCES authentication_steps ON DELETE CASCADE, email TEXT NOT NULL, code_hash BYTEA NOT NULL
);
CREATE TABLE passkey_authentication_steps (
 step_id UUID PRIMARY KEY REFERENCES authentication_steps ON DELETE CASCADE, challenge BYTEA NOT NULL
);
-- Native Google ID-token challenge uses a nonce without invented OAuth state.
CREATE TABLE google_authentication_steps (
 step_id UUID PRIMARY KEY REFERENCES authentication_steps ON DELETE CASCADE, nonce_hash BYTEA NOT NULL
);
CREATE TABLE oauth_requests (
 state_hash BYTEA PRIMARY KEY, provider TEXT NOT NULL CHECK(provider IN ('google','vk')),
 step_id UUID REFERENCES authentication_steps ON DELETE CASCADE, session_id BIGINT REFERENCES sessions ON DELETE CASCADE,
 client_binding_hash BYTEA NOT NULL, redirect_uri TEXT NOT NULL, nonce_hash BYTEA, encrypted_code_verifier BYTEA,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), expiration_timestamp TIMESTAMPTZ NOT NULL,
 CHECK ((step_id IS NULL) <> (session_id IS NULL))
);
CREATE TABLE email_change_requests (
 account_id UUID PRIMARY KEY REFERENCES accounts ON DELETE CASCADE, previous_email TEXT NOT NULL, email TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('awaiting_previous_email','awaiting_new_email')), token_hash BYTEA NOT NULL UNIQUE,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), expiration_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE password_reset_requests (
 account_id UUID PRIMARY KEY REFERENCES accounts ON DELETE CASCADE, token_hash BYTEA NOT NULL UNIQUE,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), expiration_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE account_deletion_requests (
 account_id UUID PRIMARY KEY REFERENCES accounts ON DELETE CASCADE, delete_shared_data BOOLEAN NOT NULL,
 request_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), deletion_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE totp (
 account_id UUID PRIMARY KEY REFERENCES accounts ON DELETE CASCADE, encrypted_secret BYTEA NOT NULL,
 last_used_step BIGINT NOT NULL CHECK(last_used_step >= 0), activation_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE totp_activation_requests (
 account_id UUID PRIMARY KEY REFERENCES accounts ON DELETE CASCADE, session_id BIGINT NOT NULL REFERENCES sessions ON DELETE CASCADE,
 encrypted_secret BYTEA NOT NULL, expiration_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE passkeys (
 passkey_id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE,
 credential_id BYTEA NOT NULL UNIQUE, public_key BYTEA NOT NULL, name TEXT NOT NULL,
 sign_count BIGINT NOT NULL CHECK(sign_count >= 0), backup_eligible BOOLEAN NOT NULL, backup_state BOOLEAN NOT NULL,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(), last_use_timestamp TIMESTAMPTZ,
 CHECK(NOT backup_state OR backup_eligible)
);
CREATE INDEX passkeys_account ON passkeys(account_id);
CREATE TABLE passkey_transports (
 passkey_id UUID NOT NULL REFERENCES passkeys ON DELETE CASCADE, transport TEXT NOT NULL, PRIMARY KEY(passkey_id,transport)
);
CREATE TABLE passkey_registration_requests (
 request_id UUID PRIMARY KEY, session_id BIGINT NOT NULL REFERENCES sessions ON DELETE CASCADE,
 challenge BYTEA NOT NULL, expiration_timestamp TIMESTAMPTZ NOT NULL
);
CREATE TABLE backup_codes (
 account_id UUID NOT NULL REFERENCES accounts ON DELETE CASCADE, code_hash BYTEA NOT NULL,
 generation_timestamp TIMESTAMPTZ NOT NULL, PRIMARY KEY(account_id,code_hash)
);
CREATE TABLE outbox (
 message_id UUID PRIMARY KEY, exchange TEXT NOT NULL, type TEXT NOT NULL, body JSONB NOT NULL,
 creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX outbox_creation ON outbox(creation_timestamp,message_id);
