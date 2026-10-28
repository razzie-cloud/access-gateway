-- +goose Up
ALTER TABLE webauthn_credentials ADD COLUMN device_name TEXT NOT NULL DEFAULT 'Unnamed device';

-- +goose Down
ALTER TABLE webauthn_credentials DROP COLUMN device_name;
