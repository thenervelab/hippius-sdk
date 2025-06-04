-- migrate:up

-- For security reasons, completely drop all existing tables and data
-- This removes any stored seed phrases from the database
DROP TABLE IF EXISTS encryption_keys CASCADE;
DROP TABLE IF EXISTS seed_phrases CASCADE;

-- Create new simplified schema using only subaccount_id
-- No seed phrases are stored in the database anymore
CREATE TABLE encryption_keys (
    id SERIAL PRIMARY KEY,
    subaccount_id VARCHAR(255) NOT NULL,
    encryption_key_b64 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for efficient lookups of latest encryption key per subaccount
CREATE INDEX idx_encryption_keys_subaccount_created 
ON encryption_keys(subaccount_id, created_at DESC);

-- Comments for documentation
COMMENT ON TABLE encryption_keys IS 'Stores versioned encryption keys per subaccount ID (never deleted, always use most recent)';
COMMENT ON COLUMN encryption_keys.subaccount_id IS 'Subaccount identifier for key association';
COMMENT ON COLUMN encryption_keys.encryption_key_b64 IS 'Base64 encoded encryption key';

-- migrate:down

-- Drop new table
DROP INDEX IF EXISTS idx_encryption_keys_subaccount_created;
DROP TABLE IF EXISTS encryption_keys;

-- Note: We do NOT recreate the old seed_phrases table in the down migration
-- This is intentional for security - once we've removed seed phrases from the DB,
-- we don't want to accidentally restore them