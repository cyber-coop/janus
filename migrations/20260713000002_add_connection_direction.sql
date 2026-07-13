ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS connection_direction TEXT
    CHECK (connection_direction IN ('incoming', 'outgoing'));
