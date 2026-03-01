CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mount TEXT NOT NULL,
    path TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    cipher_algorithm TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (mount, path, secret_key)
);

CREATE INDEX IF NOT EXISTS idx_secrets_mount_path ON secrets (mount, path);
