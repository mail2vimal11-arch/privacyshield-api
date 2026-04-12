-- ============================================================
-- PRIVACYSHIELD DATABASE SCHEMA
-- Run this in Supabase SQL Editor (in order, top to bottom)
-- ============================================================

-- Enable UUID extension (already enabled in Supabase by default)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ============================================================
-- SECTION 1: CORE — CUSTOMERS & API KEYS
-- ============================================================

CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    company_name VARCHAR(255),
    stripe_customer_id VARCHAR(255) UNIQUE,
    plan VARCHAR(50) DEFAULT 'free',        -- 'free' | 'personal' | 'professional' | 'business' | 'enterprise'
    plan_status VARCHAR(50) DEFAULT 'active', -- 'active' | 'cancelled' | 'past_due'
    monthly_scan_quota INTEGER DEFAULT 3,
    monthly_scans_used INTEGER DEFAULT 0,
    quota_reset_at TIMESTAMP DEFAULT (NOW() + INTERVAL '30 days'),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_customers_email ON customers(email);
CREATE INDEX idx_customers_stripe ON customers(stripe_customer_id);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,   -- Store hashed, never plaintext
    key_prefix VARCHAR(20) NOT NULL,         -- e.g. "ps_live_abc123" shown to user
    name VARCHAR(255),                       -- e.g. "Production Key"
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_api_keys_customer ON api_keys(customer_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

CREATE TABLE usage_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,        -- 'ai_model_scan' | 'web_removal_scan' | 'shadow_it_scan' | 'deletion_request'
    event_subtype VARCHAR(100),              -- e.g. 'deep_scan' | 'quick_scan'
    resource_id VARCHAR(255),               -- ID of the scan/request
    units_consumed INTEGER DEFAULT 1,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_usage_customer ON usage_events(customer_id);
CREATE INDEX idx_usage_type ON usage_events(event_type);
CREATE INDEX idx_usage_created ON usage_events(created_at DESC);

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL,
    events JSONB DEFAULT '[]'::jsonb,        -- Array of event types to send
    secret VARCHAR(255) NOT NULL,            -- For HMAC signature verification
    is_active BOOLEAN DEFAULT TRUE,
    last_triggered_at TIMESTAMP,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_webhooks_customer ON webhooks(customer_id);


-- ============================================================
-- SECTION 2: AI MODEL DATA REMOVAL
-- ============================================================

CREATE TABLE ai_model_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id VARCHAR(100) UNIQUE NOT NULL,
    model_name VARCHAR(255) NOT NULL,
    vendor VARCHAR(255) NOT NULL,
    category VARCHAR(100),                   -- 'chatbot' | 'search_engine' | 'code_assistant'
    architecture_type VARCHAR(50),           -- 'transformer' | 'rag' | 'hybrid'
    training_data_sources JSONB DEFAULT '[]'::jsonb,
    detection_methods_supported JSONB DEFAULT '[]'::jsonb,
    removal_methods_available JSONB DEFAULT '[]'::jsonb,
    gdpr_compliant VARCHAR(20) DEFAULT 'unknown', -- 'yes' | 'partial' | 'no' | 'unknown'
    known_deletion_success_rate DECIMAL(3,2),
    average_response_time_days INTEGER,
    privacy_contact VARCHAR(255),
    opt_out_url VARCHAR(500),
    live_search_enabled BOOLEAN DEFAULT FALSE,
    rag_system_active BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    last_updated TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ai_models_vendor ON ai_model_database(vendor);
CREATE INDEX idx_ai_models_category ON ai_model_database(category);

-- Seed: AI models we support scanning
INSERT INTO ai_model_database (model_id, model_name, vendor, category, architecture_type, training_data_sources, detection_methods_supported, removal_methods_available, gdpr_compliant, known_deletion_success_rate, average_response_time_days, privacy_contact, opt_out_url) VALUES
('chatgpt-4', 'ChatGPT-4', 'OpenAI', 'chatbot', 'transformer',
 '["Common Crawl", "WebText", "Books", "Reddit", "GitHub"]',
 '["prompt_injection", "extraction_attack", "metadata_analysis"]',
 '["gdpr_deletion_request", "opt_out_future_training", "source_removal"]',
 'partial', 0.23, 75, 'privacy@openai.com', 'https://openai.com/form/data-opt-out'),

('claude-sonnet-4', 'Claude Sonnet 4', 'Anthropic', 'chatbot', 'transformer',
 '["Public web data", "Books", "Academic papers"]',
 '["prompt_injection"]',
 '["source_removal"]',
 'yes', NULL, 14, 'privacy@anthropic.com', NULL),

('gemini-pro', 'Gemini Pro', 'Google', 'chatbot', 'hybrid',
 '["Google Search index", "Books", "Public web", "YouTube"]',
 '["prompt_injection", "search_integration_probe"]',
 '["gdpr_deletion_request", "google_search_removal", "source_removal"]',
 'partial', 0.42, 42, 'privacy@google.com', 'https://support.google.com/gemini/answer/13543397'),

('perplexity', 'Perplexity AI', 'Perplexity', 'search_engine', 'rag',
 '["Live web search", "Bing", "Public web"]',
 '["rag_probing", "citation_analysis"]',
 '["robots_txt_blocking", "source_removal", "index_removal_request"]',
 'unknown', 0.90, 7, 'privacy@perplexity.ai', NULL),

('llama-3', 'Llama 3', 'Meta', 'chatbot', 'transformer',
 '["Common Crawl", "GitHub", "Wikipedia"]',
 '["prompt_injection"]',
 '["source_removal"]',
 'partial', NULL, NULL, 'privacy@meta.com', NULL),

('copilot', 'GitHub Copilot', 'GitHub/Microsoft', 'code_assistant', 'transformer',
 '["Public GitHub repositories", "Stack Overflow", "Code documentation"]',
 '["prompt_injection", "extraction_attack"]',
 '["gdpr_deletion_request", "source_removal"]',
 'partial', NULL, 60, 'privacy@github.com', 'https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement');

CREATE TABLE ai_model_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    scan_id VARCHAR(100) UNIQUE NOT NULL,    -- e.g. "aiscan_abc123"
    profile_name VARCHAR(255) NOT NULL,
    profile_identifiers JSONB DEFAULT '{}'::jsonb, -- { emails: [], usernames: [], phone_numbers: [], known_urls: [] }
    models_scanned JSONB DEFAULT '[]'::jsonb,
    scan_depth VARCHAR(50) NOT NULL DEFAULT 'standard', -- 'quick' | 'standard' | 'deep'
    detection_methods JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending' | 'in_progress' | 'completed' | 'failed'
    overall_risk_score INTEGER,
    risk_level VARCHAR(50),                  -- 'low' | 'medium' | 'high' | 'critical'
    total_models_scanned INTEGER DEFAULT 0,
    models_with_data_found INTEGER DEFAULT 0,
    total_pii_instances INTEGER DEFAULT 0,
    scan_results JSONB DEFAULT '{}'::jsonb,  -- Full response payload
    created_at TIMESTAMP DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX idx_ai_scans_customer ON ai_model_scans(customer_id);
CREATE INDEX idx_ai_scans_status ON ai_model_scans(status);
CREATE INDEX idx_ai_scans_created ON ai_model_scans(created_at DESC);

CREATE TABLE ai_model_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES ai_model_scans(id) ON DELETE CASCADE,
    evidence_id VARCHAR(100) NOT NULL,
    model_id VARCHAR(100) REFERENCES ai_model_database(model_id),
    detection_method VARCHAR(100) NOT NULL,  -- 'prompt_injection' | 'extraction_attack' | 'rag_probing' | 'metadata_analysis'
    query_sent TEXT NOT NULL,
    model_response TEXT,
    pii_detected JSONB DEFAULT '[]'::jsonb,
    likely_training_sources JSONB DEFAULT '[]'::jsonb,
    confidence_score DECIMAL(3,2),
    verbatim_memorization_suspected BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ai_evidence_scan ON ai_model_evidence(scan_id);
CREATE INDEX idx_ai_evidence_model ON ai_model_evidence(model_id);

CREATE TABLE ai_removal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    removal_request_id VARCHAR(100) UNIQUE NOT NULL, -- e.g. "airem_def456"
    scan_id UUID REFERENCES ai_model_scans(id),
    profile_name VARCHAR(255) NOT NULL,
    models_targeted JSONB DEFAULT '[]'::jsonb,
    removal_strategy VARCHAR(100) NOT NULL,  -- 'gdpr_only' | 'source_removal' | 'comprehensive'
    requester_info JSONB DEFAULT '{}'::jsonb, -- { name, email, eu_resident, legal_basis }
    options JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'in_progress', -- 'in_progress' | 'completed' | 'partial' | 'failed'
    total_tasks INTEGER DEFAULT 0,
    completed_tasks INTEGER DEFAULT 0,
    pending_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    public_shame_enabled BOOLEAN DEFAULT FALSE,
    public_shame_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW(),
    estimated_completion_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_ai_removal_customer ON ai_removal_requests(customer_id);
CREATE INDEX idx_ai_removal_status ON ai_removal_requests(status);

CREATE TABLE ai_removal_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    removal_request_id UUID REFERENCES ai_removal_requests(id) ON DELETE CASCADE,
    task_id VARCHAR(100) UNIQUE NOT NULL,    -- e.g. "aitask_001"
    model_id VARCHAR(100) REFERENCES ai_model_database(model_id),
    vendor VARCHAR(255) NOT NULL,
    removal_method VARCHAR(100) NOT NULL,    -- 'gdpr_deletion_request' | 'source_removal' | 'robots_txt_blocking'
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending' | 'submitted' | 'awaiting_vendor_response' | 'vendor_responded' | 'completed' | 'failed' | 'pending_user_action'
    submitted_at TIMESTAMP,
    vendor_response_received_at TIMESTAMP,
    days_to_response INTEGER,
    vendor_response JSONB DEFAULT '{}'::jsonb,
    tracking_number VARCHAR(255),            -- e.g. "GDPR-20260404-001"
    public_tracking_url VARCHAR(500),
    next_follow_up_at TIMESTAMP,
    requires_user_action BOOLEAN DEFAULT FALSE,
    user_action_details JSONB DEFAULT '{}'::jsonb,
    public_shame_metrics JSONB DEFAULT '{}'::jsonb, -- { upvotes, comments, shares }
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX idx_ai_tasks_request ON ai_removal_tasks(removal_request_id);
CREATE INDEX idx_ai_tasks_status ON ai_removal_tasks(status);
CREATE INDEX idx_ai_tasks_vendor ON ai_removal_tasks(vendor);

CREATE TABLE ai_model_monitors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    monitor_id VARCHAR(100) UNIQUE NOT NULL, -- e.g. "aimon_ghi789"
    profile_name VARCHAR(255) NOT NULL,
    profile_identifiers JSONB DEFAULT '{}'::jsonb,
    models_to_monitor JSONB DEFAULT '[]'::jsonb,
    frequency VARCHAR(50) NOT NULL DEFAULT 'weekly', -- 'daily' | 'weekly' | 'monthly'
    alert_on JSONB DEFAULT '{"new_data_found": true, "increased_risk_score": true}'::jsonb,
    notification_channels JSONB DEFAULT '[]'::jsonb,
    status VARCHAR(50) DEFAULT 'active',     -- 'active' | 'paused' | 'cancelled'
    baseline_scan_id UUID REFERENCES ai_model_scans(id),
    baseline_models_with_data INTEGER DEFAULT 0,
    last_scan_id UUID REFERENCES ai_model_scans(id),
    next_scan_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ai_monitors_customer ON ai_model_monitors(customer_id);
CREATE INDEX idx_ai_monitors_next_scan ON ai_model_monitors(next_scan_at);
CREATE INDEX idx_ai_monitors_status ON ai_model_monitors(status);

CREATE TABLE gdpr_request_letters (
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
    send_method VARCHAR(50),                 -- 'email' | 'web_form' | 'manual'
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_gdpr_letters_task ON gdpr_request_letters(task_id);
CREATE INDEX idx_gdpr_letters_vendor ON gdpr_request_letters(vendor);

CREATE TABLE public_shame_board (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor VARCHAR(255) NOT NULL UNIQUE,
    total_requests_tracked INTEGER DEFAULT 0,
    average_response_time_days DECIMAL(5,2),
    response_rate DECIMAL(3,2),
    successful_deletions INTEGER DEFAULT 0,
    pending_requests INTEGER DEFAULT 0,
    ignored_requests INTEGER DEFAULT 0,
    longest_pending_days INTEGER DEFAULT 0,
    community_rating DECIMAL(2,1),
    community_comments INTEGER DEFAULT 0,
    trending_status VARCHAR(50),             -- 'improving' | 'stable' | 'getting_worse' | 'best_in_class'
    total_upvotes INTEGER DEFAULT 0,
    total_social_shares INTEGER DEFAULT 0,
    media_mentions INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_shame_board_rating ON public_shame_board(community_rating DESC);

-- Seed shame board with initial data
INSERT INTO public_shame_board (vendor, average_response_time_days, response_rate, trending_status) VALUES
('OpenAI', 75, 0.23, 'getting_worse'),
('Google', 42, 0.67, 'stable'),
('Anthropic', 14, 0.89, 'improving'),
('Perplexity', 7, 0.94, 'best_in_class'),
('Meta', NULL, NULL, 'stable');


-- ============================================================
-- SECTION 3: SHADOW IT DETECTION
-- ============================================================

CREATE TABLE saas_tool_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_id VARCHAR(100) UNIQUE NOT NULL,
    tool_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),                   -- 'crm' | 'communication' | 'project_management' | 'storage' | 'devtools' | 'hr'
    vendor VARCHAR(255),
    website VARCHAR(255),
    detection_signals JSONB DEFAULT '[]'::jsonb,  -- DNS patterns, email domains, OAuth scopes
    risk_level VARCHAR(50) DEFAULT 'medium', -- 'low' | 'medium' | 'high' | 'critical'
    data_residency VARCHAR(100),             -- 'us' | 'eu' | 'unknown'
    gdpr_compliant BOOLEAN DEFAULT FALSE,
    soc2_certified BOOLEAN DEFAULT FALSE,
    typical_data_stored JSONB DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_saas_tools_category ON saas_tool_database(category);
CREATE INDEX idx_saas_tools_risk ON saas_tool_database(risk_level);

-- Seed: common SaaS tools
INSERT INTO saas_tool_database (tool_id, tool_name, category, vendor, website, risk_level, gdpr_compliant, soc2_certified, typical_data_stored) VALUES
('slack', 'Slack', 'communication', 'Salesforce', 'slack.com', 'medium', TRUE, TRUE, '["messages", "files", "employee_data"]'),
('notion', 'Notion', 'project_management', 'Notion Labs', 'notion.so', 'medium', TRUE, TRUE, '["documents", "databases", "employee_data"]'),
('figma', 'Figma', 'design', 'Adobe', 'figma.com', 'low', TRUE, TRUE, '["design_files", "employee_data"]'),
('hubspot', 'HubSpot', 'crm', 'HubSpot', 'hubspot.com', 'high', TRUE, TRUE, '["customer_data", "contact_info", "emails"]'),
('salesforce', 'Salesforce', 'crm', 'Salesforce', 'salesforce.com', 'high', TRUE, TRUE, '["customer_data", "contracts", "financial_data"]'),
('dropbox', 'Dropbox', 'storage', 'Dropbox', 'dropbox.com', 'high', TRUE, TRUE, '["files", "documents", "sensitive_data"]'),
('zoom', 'Zoom', 'communication', 'Zoom', 'zoom.us', 'medium', TRUE, TRUE, '["meeting_recordings", "transcripts", "employee_data"]'),
('github', 'GitHub', 'devtools', 'Microsoft', 'github.com', 'critical', TRUE, TRUE, '["source_code", "api_keys", "intellectual_property"]'),
('linear', 'Linear', 'project_management', 'Linear', 'linear.app', 'low', TRUE, FALSE, '["issues", "roadmaps", "employee_data"]'),
('intercom', 'Intercom', 'customer_support', 'Intercom', 'intercom.com', 'high', TRUE, TRUE, '["customer_data", "chat_logs", "email"]');

CREATE TABLE shadow_it_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    scan_id VARCHAR(100) UNIQUE NOT NULL,    -- e.g. "scan_abc123"
    domain VARCHAR(255) NOT NULL,            -- e.g. "acmecorp.com"
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_tools_found INTEGER DEFAULT 0,
    high_risk_tools INTEGER DEFAULT 0,
    compliance_score INTEGER,                -- 0-100
    scan_methods JSONB DEFAULT '[]'::jsonb,  -- ['dns', 'email_headers', 'linkedin', 'chrome_extensions']
    results JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX idx_shadow_scans_customer ON shadow_it_scans(customer_id);
CREATE INDEX idx_shadow_scans_domain ON shadow_it_scans(domain);
CREATE INDEX idx_shadow_scans_created ON shadow_it_scans(created_at DESC);

CREATE TABLE shadow_it_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES shadow_it_scans(id) ON DELETE CASCADE,
    tool_id VARCHAR(100) REFERENCES saas_tool_database(tool_id),
    detection_method VARCHAR(100),           -- 'dns_mx' | 'dns_cname' | 'linkedin' | 'email_header'
    evidence JSONB DEFAULT '{}'::jsonb,
    confidence_score DECIMAL(3,2),
    risk_level VARCHAR(50),
    estimated_users INTEGER,
    data_categories JSONB DEFAULT '[]'::jsonb,
    remediation_steps JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_shadow_findings_scan ON shadow_it_findings(scan_id);
CREATE INDEX idx_shadow_findings_tool ON shadow_it_findings(tool_id);


-- ============================================================
-- SECTION 4: DATA DELETION
-- ============================================================

CREATE TABLE deletion_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id VARCHAR(100) UNIQUE NOT NULL,
    platform_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),                   -- 'crm' | 'marketing' | 'support' | 'analytics'
    api_type VARCHAR(50),                    -- 'rest' | 'graphql' | 'soap'
    gdpr_endpoint_available BOOLEAN DEFAULT FALSE,
    bulk_deletion_supported BOOLEAN DEFAULT FALSE,
    requires_oauth BOOLEAN DEFAULT FALSE,
    requires_api_key BOOLEAN DEFAULT FALSE,
    documentation_url VARCHAR(500),
    average_deletion_time_seconds INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_deletion_integrations_category ON deletion_integrations(category);

-- Seed: supported platforms
INSERT INTO deletion_integrations (integration_id, platform_name, category, gdpr_endpoint_available, bulk_deletion_supported, requires_api_key) VALUES
('salesforce', 'Salesforce', 'crm', TRUE, TRUE, TRUE),
('hubspot', 'HubSpot CRM', 'crm', TRUE, TRUE, TRUE),
('intercom', 'Intercom', 'customer_support', TRUE, FALSE, TRUE),
('mailchimp', 'Mailchimp', 'marketing', TRUE, FALSE, TRUE),
('klaviyo', 'Klaviyo', 'marketing', TRUE, TRUE, TRUE),
('zendesk', 'Zendesk', 'support', TRUE, FALSE, TRUE),
('mixpanel', 'Mixpanel', 'analytics', TRUE, TRUE, TRUE),
('segment', 'Segment', 'analytics', TRUE, TRUE, TRUE),
('amplitude', 'Amplitude', 'analytics', TRUE, FALSE, TRUE),
('pipedrive', 'Pipedrive', 'crm', TRUE, FALSE, TRUE);

CREATE TABLE deletion_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    job_id VARCHAR(100) UNIQUE NOT NULL,     -- e.g. "del_abc123"
    subject_email VARCHAR(255) NOT NULL,     -- The person whose data is being deleted
    subject_identifiers JSONB DEFAULT '{}'::jsonb, -- Additional identifiers
    platforms JSONB DEFAULT '[]'::jsonb,     -- Which platforms to delete from
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_records_found INTEGER DEFAULT 0,
    total_records_deleted INTEGER DEFAULT 0,
    legal_basis VARCHAR(255) DEFAULT 'GDPR Article 17',
    compliance_certificate_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX idx_deletion_jobs_customer ON deletion_jobs(customer_id);
CREATE INDEX idx_deletion_jobs_email ON deletion_jobs(subject_email);
CREATE INDEX idx_deletion_jobs_status ON deletion_jobs(status);

CREATE TABLE deletion_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID REFERENCES deletion_jobs(id) ON DELETE CASCADE,
    integration_id VARCHAR(100) REFERENCES deletion_integrations(integration_id),
    platform_record_id VARCHAR(500),         -- The ID in the external platform
    record_type VARCHAR(100),                -- 'contact' | 'lead' | 'user' | 'subscriber'
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending' | 'found' | 'deleted' | 'not_found' | 'error'
    deleted_at TIMESTAMP,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_deletion_records_job ON deletion_records(job_id);
CREATE INDEX idx_deletion_records_status ON deletion_records(status);

CREATE TABLE platform_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    integration_id VARCHAR(100) REFERENCES deletion_integrations(integration_id),
    credential_type VARCHAR(50) NOT NULL,    -- 'api_key' | 'oauth_token' | 'oauth_refresh'
    encrypted_value TEXT NOT NULL,           -- ALWAYS store encrypted
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_platform_creds_customer ON platform_credentials(customer_id);
CREATE INDEX idx_platform_creds_integration ON platform_credentials(integration_id);


-- ============================================================
-- SECTION 5: WEB DATA REMOVAL
-- ============================================================

CREATE TABLE data_broker_database (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_id VARCHAR(100) UNIQUE NOT NULL,
    broker_name VARCHAR(255) NOT NULL,
    website VARCHAR(255) NOT NULL,
    opt_out_url VARCHAR(500),
    opt_out_method VARCHAR(100),             -- 'web_form' | 'email' | 'automated' | 'manual_only'
    automated_removal_supported BOOLEAN DEFAULT FALSE,
    average_removal_days INTEGER,
    recurrence_months INTEGER,               -- How often data re-appears
    risk_level VARCHAR(50) DEFAULT 'medium',
    data_types JSONB DEFAULT '[]'::jsonb,    -- What data they typically hold
    country VARCHAR(100) DEFAULT 'US',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_brokers_automated ON data_broker_database(automated_removal_supported);
CREATE INDEX idx_brokers_country ON data_broker_database(country);

-- Seed: top data brokers
INSERT INTO data_broker_database (broker_id, broker_name, website, opt_out_method, automated_removal_supported, average_removal_days, data_types) VALUES
('spokeo', 'Spokeo', 'spokeo.com', 'web_form', TRUE, 3, '["name", "address", "phone", "email", "relatives"]'),
('whitepages', 'WhitePages', 'whitepages.com', 'web_form', TRUE, 3, '["name", "address", "phone", "age"]'),
('intelius', 'Intelius', 'intelius.com', 'web_form', FALSE, 7, '["name", "address", "phone", "criminal_records"]'),
('beenverified', 'BeenVerified', 'beenverified.com', 'web_form', TRUE, 5, '["name", "address", "email", "social_profiles"]'),
('peoplefinder', 'PeopleFinder', 'peoplefinder.com', 'web_form', FALSE, 7, '["name", "address", "phone"]'),
('radaris', 'Radaris', 'radaris.com', 'web_form', TRUE, 3, '["name", "address", "phone", "relatives", "employment"]'),
('mylife', 'MyLife', 'mylife.com', 'email', FALSE, 30, '["name", "address", "reputation_score", "family"]'),
('truthfinder', 'TruthFinder', 'truthfinder.com', 'web_form', FALSE, 7, '["name", "address", "criminal_records", "social"]'),
('instantcheckmate', 'Instant Checkmate', 'instantcheckmate.com', 'web_form', FALSE, 5, '["name", "address", "criminal_records"]'),
('fastpeoplesearch', 'FastPeopleSearch', 'fastpeoplesearch.com', 'automated', TRUE, 1, '["name", "address", "phone", "relatives"]');

CREATE TABLE web_removal_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    profile_id VARCHAR(100) UNIQUE NOT NULL, -- e.g. "prof_abc123"
    profile_name VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    emails JSONB DEFAULT '[]'::jsonb,
    phone_numbers JSONB DEFAULT '[]'::jsonb,
    addresses JSONB DEFAULT '[]'::jsonb,     -- Current and former addresses
    date_of_birth DATE,
    social_profiles JSONB DEFAULT '[]'::jsonb,
    monitoring_enabled BOOLEAN DEFAULT FALSE,
    monitoring_frequency VARCHAR(50) DEFAULT 'monthly',
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_web_profiles_customer ON web_removal_profiles(customer_id);

CREATE TABLE web_removal_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    scan_id VARCHAR(100) UNIQUE NOT NULL,    -- e.g. "wscan_abc123"
    profile_id UUID REFERENCES web_removal_profiles(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_brokers_scanned INTEGER DEFAULT 0,
    listings_found INTEGER DEFAULT 0,
    high_risk_listings INTEGER DEFAULT 0,
    scan_results JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE INDEX idx_web_scans_customer ON web_removal_scans(customer_id);
CREATE INDEX idx_web_scans_profile ON web_removal_scans(profile_id);
CREATE INDEX idx_web_scans_created ON web_removal_scans(created_at DESC);

CREATE TABLE web_removal_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES web_removal_scans(id) ON DELETE CASCADE,
    broker_id VARCHAR(100) REFERENCES data_broker_database(broker_id),
    listing_url VARCHAR(500),
    data_found JSONB DEFAULT '{}'::jsonb,    -- What data was found at this listing
    risk_level VARCHAR(50),
    status VARCHAR(50) DEFAULT 'found',      -- 'found' | 'removal_submitted' | 'removed' | 'reappeared'
    removal_submitted_at TIMESTAMP,
    removal_confirmed_at TIMESTAMP,
    check_again_at TIMESTAMP,               -- When to re-check for reappearance
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_web_listings_scan ON web_removal_listings(scan_id);
CREATE INDEX idx_web_listings_broker ON web_removal_listings(broker_id);
CREATE INDEX idx_web_listings_status ON web_removal_listings(status);

CREATE TABLE web_removal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    removal_id VARCHAR(100) UNIQUE NOT NULL, -- e.g. "wrem_abc123"
    profile_id UUID REFERENCES web_removal_profiles(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES web_removal_scans(id),
    brokers_targeted JSONB DEFAULT '[]'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'in_progress',
    total_brokers INTEGER DEFAULT 0,
    completed_brokers INTEGER DEFAULT 0,
    failed_brokers INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX idx_web_removals_customer ON web_removal_requests(customer_id);
CREATE INDEX idx_web_removals_status ON web_removal_requests(status);


-- ============================================================
-- SECTION 6: ROW LEVEL SECURITY (RLS)
-- Ensures each customer can only see their own data
-- ============================================================

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_model_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_model_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_removal_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_removal_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_model_monitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE gdpr_request_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE shadow_it_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE shadow_it_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE deletion_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_removal_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_removal_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_removal_listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_removal_requests ENABLE ROW LEVEL SECURITY;

-- Note: RLS policies using auth.uid() should be added once you connect
-- Supabase Auth. For now the service_role key bypasses RLS for backend use.
-- Public tables (no RLS needed — read-only reference data):
-- ai_model_database, saas_tool_database, deletion_integrations,
-- data_broker_database, public_shame_board


-- ============================================================
-- SECTION 7: HELPER FUNCTIONS
-- ============================================================

-- Auto-update 'updated_at' timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_customers_updated_at
    BEFORE UPDATE ON customers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_ai_monitors_updated_at
    BEFORE UPDATE ON ai_model_monitors
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_web_profiles_updated_at
    BEFORE UPDATE ON web_removal_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_platform_creds_updated_at
    BEFORE UPDATE ON platform_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================
-- DONE! Tables created:
-- Core:             customers, api_keys, usage_events, webhooks
-- AI Model:         ai_model_database (seeded), ai_model_scans, ai_model_evidence,
--                   ai_removal_requests, ai_removal_tasks, ai_model_monitors,
--                   gdpr_request_letters, public_shame_board (seeded)
-- Shadow IT:        saas_tool_database (seeded), shadow_it_scans, shadow_it_findings
-- Data Deletion:    deletion_integrations (seeded), deletion_jobs, deletion_records,
--                   platform_credentials
-- Web Removal:      data_broker_database (seeded), web_removal_profiles,
--                   web_removal_scans, web_removal_listings, web_removal_requests
-- ============================================================
