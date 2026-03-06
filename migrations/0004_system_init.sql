CREATE TABLE IF NOT EXISTS system_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    initialized_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO system_state (id, initialized_at)
VALUES (1, NULL)
ON CONFLICT (id) DO NOTHING;

-- Preserve behavior for existing installations that already have a bootstrap admin token.
UPDATE system_state
SET initialized_at = COALESCE(initialized_at, NOW()),
    updated_at = NOW()
WHERE id = 1
  AND EXISTS (
      SELECT 1
      FROM service_tokens
      WHERE bootstrap_slot = 1
  );
