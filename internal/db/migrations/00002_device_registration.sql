-- +goose Up
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE;
-- Preserve the original bootstrap account as administrator on existing installs.
UPDATE users SET is_admin = TRUE WHERE id = (
    SELECT id FROM users ORDER BY created_at, username LIMIT 1
);

CREATE TABLE registration_links (
    token_hash TEXT PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX registration_links_user_id_idx ON registration_links(user_id);

-- +goose Down
DROP TABLE registration_links;
ALTER TABLE users DROP COLUMN is_admin;
