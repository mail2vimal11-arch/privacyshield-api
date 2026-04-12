-- ============================================================
-- PRIVACYSHIELD — DAY 3 SQL PATCH
-- Run this in Supabase SQL Editor AFTER schema.sql
-- ============================================================


-- ----------------------------------------------------------------
-- 1. increment_scan_count function
-- Called by the API after each scan to track usage
-- ----------------------------------------------------------------

CREATE OR REPLACE FUNCTION increment_scan_count(customer_id UUID)
RETURNS void AS $$
BEGIN
    UPDATE customers
    SET monthly_scans_used = monthly_scans_used + 1
    WHERE id = customer_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ----------------------------------------------------------------
-- 2. reset_monthly_quotas function
-- Run this on a schedule (1st of each month) to reset usage counters
-- ----------------------------------------------------------------

CREATE OR REPLACE FUNCTION reset_monthly_quotas()
RETURNS void AS $$
BEGIN
    UPDATE customers
    SET
        monthly_scans_used = 0,
        quota_reset_at = NOW() + INTERVAL '30 days'
    WHERE quota_reset_at <= NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;


-- ----------------------------------------------------------------
-- 3. get_shame_board_stats view
-- Powers the public shame dashboard endpoint
-- ----------------------------------------------------------------

CREATE OR REPLACE VIEW shame_board_live AS
SELECT
    psb.vendor,
    psb.total_requests_tracked,
    psb.average_response_time_days,
    psb.response_rate,
    psb.successful_deletions,
    psb.pending_requests,
    psb.ignored_requests,
    psb.community_rating,
    psb.trending_status,
    -- Live count from actual removal tasks
    COUNT(art.id) AS live_total_tasks,
    COUNT(CASE WHEN art.status = 'completed' THEN 1 END) AS live_completed,
    COUNT(CASE WHEN art.status = 'awaiting_vendor_response' THEN 1 END) AS live_awaiting,
    AVG(art.days_to_response) AS live_avg_response_days
FROM public_shame_board psb
LEFT JOIN ai_removal_tasks art ON LOWER(art.vendor) = LOWER(psb.vendor)
GROUP BY
    psb.vendor,
    psb.total_requests_tracked,
    psb.average_response_time_days,
    psb.response_rate,
    psb.successful_deletions,
    psb.pending_requests,
    psb.ignored_requests,
    psb.community_rating,
    psb.trending_status;


-- ----------------------------------------------------------------
-- 4. GDPR letters table (if not already created from schema.sql)
-- ----------------------------------------------------------------

CREATE TABLE IF NOT EXISTS gdpr_request_letters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID REFERENCES ai_removal_tasks(id) ON DELETE CASCADE,
    vendor VARCHAR(255) NOT NULL,
    subject_line TEXT NOT NULL,
    body TEXT NOT NULL,
    recipient_email VARCHAR(255),
    cc_emails JSONB DEFAULT '[]'::jsonb,
    web_form_url VARCHAR(500),
    legal_basis VARCHAR(255) DEFAULT 'GDPR Article 17 - Right to Erasure',
    pdf_url VARCHAR(500),
    sent_at TIMESTAMP,
    send_method VARCHAR(50),
    email_send_result JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gdpr_letters_task ON gdpr_request_letters(task_id);
CREATE INDEX IF NOT EXISTS idx_gdpr_letters_vendor ON gdpr_request_letters(vendor);


-- ----------------------------------------------------------------
-- 5. Add email_send_result column to gdpr_request_letters
-- (in case table already existed without it)
-- ----------------------------------------------------------------

ALTER TABLE gdpr_request_letters
ADD COLUMN IF NOT EXISTS email_send_result JSONB DEFAULT '{}'::jsonb;


-- ----------------------------------------------------------------
-- Done! Day 3 patch applied.
-- ----------------------------------------------------------------
