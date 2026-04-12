-- PrivacyShield — Day 7 Schema Patch
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New query)

-- Table: web_removal_jobs
-- Tracks all data broker opt-out requests submitted per customer
CREATE TABLE IF NOT EXISTS web_removal_jobs (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id              UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    full_name                TEXT NOT NULL,
    email                    TEXT NOT NULL,
    total_brokers            INTEGER DEFAULT 0,
    emails_sent              INTEGER DEFAULT 0,
    url_only_brokers         INTEGER DEFAULT 0,
    estimated_completion_days INTEGER DEFAULT 30,
    estimated_complete_date  TIMESTAMPTZ,
    scan_type                TEXT DEFAULT 'removal_request',  -- 'exposure_scan' or 'removal_request'
    status                   TEXT DEFAULT 'in_progress',      -- 'in_progress', 'completed', 'partial'
    risk_score               INTEGER,                         -- 0–100, used for exposure scans
    risk_level               TEXT,                            -- 'LOW', 'MEDIUM', 'HIGH'
    estimated_exposures      INTEGER,
    pdf_ready                BOOLEAN DEFAULT FALSE,
    created_at               TIMESTAMPTZ DEFAULT NOW(),
    updated_at               TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE web_removal_jobs ENABLE ROW LEVEL SECURITY;

-- Index for fast customer lookups
CREATE INDEX IF NOT EXISTS idx_web_removal_jobs_customer
    ON web_removal_jobs(customer_id);

CREATE INDEX IF NOT EXISTS idx_web_removal_jobs_created
    ON web_removal_jobs(created_at DESC);

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_web_removal_jobs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_web_removal_jobs_updated_at ON web_removal_jobs;
CREATE TRIGGER set_web_removal_jobs_updated_at
    BEFORE UPDATE ON web_removal_jobs
    FOR EACH ROW EXECUTE FUNCTION update_web_removal_jobs_updated_at();
