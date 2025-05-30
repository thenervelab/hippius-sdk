-- migrate:up

-- Table to store base64 encoded seed phrases (hashed for indexing)
CREATE TABLE seed_phrases (
    id SERIAL PRIMARY KEY,
    seed_hash VARCHAR(64) UNIQUE NOT NULL,
    seed_phrase_b64 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table to store encryption keys associated with each seed phrase (versioned, never deleted)
CREATE TABLE encryption_keys (
    id SERIAL PRIMARY KEY,
    seed_hash VARCHAR(64) NOT NULL,
    encryption_key_b64 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seed_hash) REFERENCES seed_phrases(seed_hash) ON DELETE CASCADE
);

-- Index for efficient lookups of latest encryption key per seed phrase
CREATE INDEX idx_encryption_keys_seed_hash_created 
ON encryption_keys(seed_hash, created_at DESC);

-- Comments for documentation
COMMENT ON TABLE seed_phrases IS 'Stores hashed seed phrases with base64 encoded values';
COMMENT ON TABLE encryption_keys IS 'Stores versioned encryption keys per seed phrase (never deleted, always use most recent)';
COMMENT ON COLUMN seed_phrases.seed_hash IS 'SHA-256 hash of the seed phrase for indexing';
COMMENT ON COLUMN seed_phrases.seed_phrase_b64 IS 'Base64 encoded seed phrase';
COMMENT ON COLUMN encryption_keys.seed_hash IS 'Reference to the seed phrase hash';
COMMENT ON COLUMN encryption_keys.encryption_key_b64 IS 'Base64 encoded encryption key';

-- migrate:down

-- Drop tables in reverse order due to foreign key constraints
DROP INDEX IF EXISTS idx_encryption_keys_seed_hash_created;
DROP TABLE IF EXISTS encryption_keys;
DROP TABLE IF EXISTS seed_phrases;