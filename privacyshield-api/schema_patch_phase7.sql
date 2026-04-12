-- Phase 7: Security hardening tables

-- Threat events from probe detector
CREATE TABLE IF NOT EXISTS threat_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE SET NULL,
    query_text TEXT,
    probe_score FLOAT DEFAULT 0.0,
    pattern_matches JSONB DEFAULT '[]',
    semantic_similarity FLOAT DEFAULT 0.0,
    disposition TEXT DEFAULT 'passed' CHECK (disposition IN ('passed', 'flagged', 'blocked')),
    judge_score FLOAT,
    dpo_pair_generated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_customer ON threat_events(customer_id);
CREATE INDEX IF NOT EXISTS idx_threat_disposition ON threat_events(disposition);
CREATE INDEX IF NOT EXISTS idx_threat_created ON threat_events(created_at);

-- System configuration (model checksums, retraining state)
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Grant access
GRANT ALL ON threat_events TO service_role;
GRANT ALL ON system_config TO service_role;
