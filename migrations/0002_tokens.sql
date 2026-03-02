CREATE TABLE IF NOT EXISTS service_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ,
    bootstrap_slot SMALLINT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_token_policies (
    token_id UUID NOT NULL REFERENCES service_tokens(id) ON DELETE CASCADE,
    mount TEXT NOT NULL,
    path_prefix TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (token_id, mount, path_prefix)
);

CREATE INDEX IF NOT EXISTS idx_service_tokens_expires_at ON service_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_service_token_policies_token ON service_token_policies (token_id);
