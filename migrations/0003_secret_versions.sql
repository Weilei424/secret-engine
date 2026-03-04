ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

ALTER TABLE secrets
    DROP CONSTRAINT IF EXISTS secrets_mount_path_secret_key_key;

ALTER TABLE secrets
    ADD CONSTRAINT secrets_mount_path_secret_key_version_key
    UNIQUE (mount, path, secret_key, version);

CREATE INDEX IF NOT EXISTS idx_secrets_mount_path_key_version
    ON secrets (mount, path, secret_key, version DESC);

