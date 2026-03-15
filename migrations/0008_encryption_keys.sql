CREATE TABLE IF NOT EXISTS encryption_keys (
    key_id TEXT PRIMARY KEY,
    derivation_algorithm TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_encryption_keys_single_active
    ON encryption_keys ((deactivated_at IS NULL))
    WHERE deactivated_at IS NULL;

INSERT INTO encryption_keys (key_id, derivation_algorithm, created_at, activated_at)
VALUES ('static-passphrase-v1', 'aes-256-gcm+argon2id-v1', NOW(), NOW())
ON CONFLICT (key_id) DO NOTHING;

ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS key_id TEXT;

UPDATE secrets
SET key_id = CASE
    WHEN position(':' IN cipher_algorithm) > 0 THEN split_part(cipher_algorithm, ':', 2)
    ELSE 'static-passphrase-v1'
END
WHERE key_id IS NULL;

ALTER TABLE secrets
    ALTER COLUMN key_id SET NOT NULL;

ALTER TABLE secrets
    ADD CONSTRAINT secrets_key_id_fkey
    FOREIGN KEY (key_id) REFERENCES encryption_keys (key_id);

CREATE INDEX IF NOT EXISTS idx_secrets_key_id ON secrets (key_id);
