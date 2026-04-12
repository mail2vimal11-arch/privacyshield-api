-- Phase 6A: Machine Unlearning Engine
-- Run this in the Supabase SQL editor to add the unlearning_requests table.

CREATE TABLE IF NOT EXISTS unlearning_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    subject_email TEXT NOT NULL,
    subject_name TEXT,
    platforms JSONB DEFAULT '[]',
    platform_results JSONB DEFAULT '{}',
    status TEXT DEFAULT 'processing' CHECK (status IN ('processing','submitted','verifying','verified','failed')),
    reason TEXT DEFAULT 'GDPR Article 17 - Right to Erasure',
    certificate_id TEXT UNIQUE,
    submitted_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_unlearning_customer ON unlearning_requests(customer_id);
CREATE INDEX IF NOT EXISTS idx_unlearning_email ON unlearning_requests(subject_email);
