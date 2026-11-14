-- +goose Up
-- NULL identifies an invitation that creates a regular user at enrollment.
ALTER TABLE registration_links ALTER COLUMN user_id DROP NOT NULL;

-- +goose Down
DELETE FROM registration_links WHERE user_id IS NULL;
ALTER TABLE registration_links ALTER COLUMN user_id SET NOT NULL;
