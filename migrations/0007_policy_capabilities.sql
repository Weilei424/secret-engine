ALTER TABLE service_token_policies
    ADD COLUMN IF NOT EXISTS capabilities TEXT[] NOT NULL
    DEFAULT ARRAY['read', 'list', 'write', 'delete', 'undelete', 'destroy']::TEXT[];

UPDATE service_token_policies
SET capabilities = ARRAY['read', 'list', 'write', 'delete', 'undelete', 'destroy']::TEXT[]
WHERE capabilities IS NULL OR cardinality(capabilities) = 0;

CREATE INDEX IF NOT EXISTS idx_service_token_policies_capabilities
    ON service_token_policies USING GIN (capabilities);
