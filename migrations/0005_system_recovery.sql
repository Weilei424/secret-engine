ALTER TABLE system_state
    ADD COLUMN IF NOT EXISTS recovery_key_hash TEXT;
