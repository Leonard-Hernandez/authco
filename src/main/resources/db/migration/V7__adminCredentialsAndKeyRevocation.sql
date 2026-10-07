-- Credentials for the admin API. Generated on first startup; only the
-- BCrypt hash is stored, the clear password is shown once in the log.
CREATE TABLE admin_credentials (
    username VARCHAR(50) PRIMARY KEY,
    password_hash VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- A revoked key is no longer published on the JWKS, so every token it signed
-- stops validating at once. Kept as a timestamp for auditing.
ALTER TABLE jwk_keys ADD COLUMN revoked_at TIMESTAMP NULL;
