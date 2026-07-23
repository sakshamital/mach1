"""
YOUR SENTINEL — PostgreSQL schema definitions.

Contains complete SCHEMA_SQL for all tables with UUID primary keys,
JSONB fields, indexes, and extensions required for production deployment.
"""

from __future__ import annotations

SCHEMA_SQL: str = """
-- YOUR SENTINEL v8.0 Database Schema
-- Run migrations.sql on Render PostgreSQL

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Scan logs: every analysis from all 4 AIs
CREATE TABLE IF NOT EXISTS scan_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id VARCHAR(32) UNIQUE NOT NULL,
    input_text TEXT,
    input_type VARCHAR(20) DEFAULT 'text',
    has_image BOOLEAN DEFAULT FALSE,
    image_filename VARCHAR(255),
    risk_score REAL DEFAULT 0,
    risk_level VARCHAR(20) DEFAULT 'LOW',
    category VARCHAR(64) DEFAULT 'unknown',
    verdict VARCHAR(32) DEFAULT 'UNKNOWN',
    is_scam BOOLEAN DEFAULT FALSE,
    verify_mode BOOLEAN DEFAULT FALSE,
    behaviour_scores JSONB DEFAULT '{}',
    behaviour_triggers JSONB DEFAULT '[]',
    mutation_matches JSONB DEFAULT '[]',
    mismatch_alerts JSONB DEFAULT '[]',
    url_threats JSONB DEFAULT '[]',
    extracted_urls JSONB DEFAULT '[]',
    ai1_result JSONB DEFAULT '{}',
    ai2_result JSONB DEFAULT '{}',
    ai3_result JSONB DEFAULT '{}',
    ai4_result JSONB DEFAULT '{}',
    unified_verdict JSONB DEFAULT '{}',
    forensic_narrative TEXT,
    recommended_actions JSONB DEFAULT '[]',
    suspect_phone VARCHAR(32),
    suspect_upi VARCHAR(128),
    suspect_website VARCHAR(512),
    summary TEXT,
    pipeline_duration_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_logs_risk_level ON scan_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_logs_is_scam ON scan_logs(is_scam);

-- Victim reports: page 2 complaint generation
CREATE TABLE IF NOT EXISTS victim_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id VARCHAR(32) UNIQUE NOT NULL,
    scan_id VARCHAR(32) REFERENCES scan_logs(scan_id) ON DELETE SET NULL,
    victim_name VARCHAR(255) NOT NULL,
    victim_mobile VARCHAR(20) NOT NULL,
    victim_email VARCHAR(255),
    victim_address TEXT,
    victim_city VARCHAR(128),
    victim_state VARCHAR(128),
    victim_pin VARCHAR(10),
    id_proof_type VARCHAR(64),
    id_proof_number VARCHAR(64),
    incident_date DATE,
    incident_time VARCHAR(16),
    amount_lost DECIMAL(15, 2) DEFAULT 0,
    payment_method VARCHAR(64),
    incident_details TEXT,
    suspect_phone VARCHAR(32),
    suspect_upi VARCHAR(128),
    suspect_website VARCHAR(512),
    suspect_details TEXT,
    complaint_text TEXT,
    complaint_sections JSONB DEFAULT '{}',
    generated_by VARCHAR(32) DEFAULT 'groq',
    status VARCHAR(32) DEFAULT 'generated',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_victim_reports_scan_id ON victim_reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_victim_reports_report_id ON victim_reports(report_id);

-- Known URLs cache (AI 3)
CREATE TABLE IF NOT EXISTS known_urls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    url_hash VARCHAR(64) UNIQUE NOT NULL,
    url TEXT NOT NULL,
    domain VARCHAR(255),
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score REAL DEFAULT 0,
    safe_browsing_result JSONB DEFAULT '{}',
    virustotal_result JSONB DEFAULT '{}',
    pattern_result JSONB DEFAULT '{}',
    threat_types JSONB DEFAULT '[]',
    checked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    hit_count INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_known_urls_domain ON known_urls(domain);
CREATE INDEX IF NOT EXISTS idx_known_urls_malicious ON known_urls(is_malicious);

-- Community patterns (user-confirmed scams)
CREATE TABLE IF NOT EXISTS community_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pattern_hash VARCHAR(64) UNIQUE NOT NULL,
    text_sample TEXT NOT NULL,
    category VARCHAR(64),
    confirmed_count INTEGER DEFAULT 1,
    risk_boost REAL DEFAULT 5.0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_community_patterns_category ON community_patterns(category);

-- Learned patterns (auto from news scraping)
CREATE TABLE IF NOT EXISTS learned_patterns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source VARCHAR(64) DEFAULT 'news_scraper',
    pattern_text TEXT NOT NULL,
    category VARCHAR(64),
    keywords JSONB DEFAULT '[]',
    severity VARCHAR(20) DEFAULT 'MODERATE',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_learned_patterns_category ON learned_patterns(category);

-- News articles
CREATE TABLE IF NOT EXISTS news_articles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    article_id VARCHAR(64) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    content TEXT,
    source VARCHAR(128),
    source_url TEXT,
    category VARCHAR(64),
    severity VARCHAR(20) DEFAULT 'MODERATE',
    is_hardcoded BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMPTZ,
    scraped_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_news_severity ON news_articles(severity);
CREATE INDEX IF NOT EXISTS idx_news_category ON news_articles(category);
CREATE INDEX IF NOT EXISTS idx_news_published ON news_articles(published_at DESC);

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    notification_id VARCHAR(64) UNIQUE NOT NULL,
    type VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    severity VARCHAR(20) DEFAULT 'MODERATE',
    is_read BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    scan_id VARCHAR(32),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(is_read) WHERE is_read = FALSE;
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);

-- Mismatch log
CREATE TABLE IF NOT EXISTS mismatch_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id VARCHAR(32),
    mismatch_type VARCHAR(32),
    claimed_entity VARCHAR(128),
    claimed_value VARCHAR(512),
    actual_entity VARCHAR(128),
    actual_value VARCHAR(512),
    severity VARCHAR(20) DEFAULT 'HIGH',
    details JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mismatch_log_scan_id ON mismatch_log(scan_id);

-- System stats (key-value dashboard)
CREATE TABLE IF NOT EXISTS system_stats (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    stat_key VARCHAR(64) UNIQUE NOT NULL,
    stat_value JSONB DEFAULT '{}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed default stats
INSERT INTO system_stats (stat_key, stat_value) VALUES
    ('total_scans', '{"count": 0}'),
    ('scams_detected', '{"count": 0}'),
    ('urls_checked', '{"count": 0}'),
    ('reports_generated', '{"count": 0}'),
    ('community_confirmations', '{"count": 0}'),
    ('critical_alerts', '{"count": 0}'),
    ('family_scams', '{"count": 0}'),
    ('news_articles', '{"count": 0}')
ON CONFLICT (stat_key) DO NOTHING;
"""

TABLE_NAMES: list[str] = [
    "scan_logs",
    "victim_reports",
    "known_urls",
    "community_patterns",
    "learned_patterns",
    "news_articles",
    "notifications",
    "mismatch_log",
    "system_stats",
]
