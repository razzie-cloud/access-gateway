-- +goose Up
ALTER TABLE users ADD CONSTRAINT users_username_format_check CHECK (
    octet_length(username) BETWEEN 1 AND 64
    AND username COLLATE "C" !~ '[^A-Za-z0-9_.-]'
);

-- Building the index rejects existing case-only duplicates. Goose runs this
-- migration transactionally, so a conflict leaves the original schema intact.
CREATE UNIQUE INDEX users_username_ci_key ON users (lower(username COLLATE "C"));
ALTER TABLE users DROP CONSTRAINT users_username_key;

-- +goose Down
ALTER TABLE users ADD CONSTRAINT users_username_key UNIQUE (username);
DROP INDEX users_username_ci_key;
ALTER TABLE users DROP CONSTRAINT users_username_format_check;
