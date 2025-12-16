-- +goose Up
CREATE TABLE app_states (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE users (
    id BYTEA PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);

CREATE TABLE webauthn_credentials (
    id BIGSERIAL PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    credential_json BYTEA NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX webauthn_credentials_user_id_idx
    ON webauthn_credentials (user_id);

-- +goose Down
DROP TABLE IF EXISTS webauthn_credentials;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS app_states;
