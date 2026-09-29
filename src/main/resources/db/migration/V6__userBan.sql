-- A ban is recorded as a timestamp instead of a flag: NULL means active,
-- a value means banned and records when it happened.
ALTER TABLE users ADD COLUMN banned_at TIMESTAMP NULL;
ALTER TABLE users ADD COLUMN ban_reason VARCHAR(255) NULL;

-- Carry over any user already disabled through the legacy flag.
UPDATE users SET banned_at = CURRENT_TIMESTAMP, ban_reason = 'migrated from enabled = false' WHERE enabled = FALSE;

-- The legacy flag was never read; banned_at is now the single source of truth.
ALTER TABLE users DROP COLUMN enabled;
