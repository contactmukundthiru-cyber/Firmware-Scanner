-- Initial schema for Firmware Scanner

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    artifact_hash VARCHAR(64),
    artifact_size BIGINT NOT NULL DEFAULT 0,
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    capability_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    is_dormant BOOLEAN NOT NULL DEFAULT FALSE,
    evidence_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_capability_type ON findings(capability_type);
CREATE INDEX idx_findings_severity ON findings(severity);

-- Claim verdicts table
CREATE TABLE IF NOT EXISTS claim_verdicts (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    claim_type VARCHAR(100) NOT NULL,
    compatible VARCHAR(20) NOT NULL,
    failing_conditions JSONB,
    evidence_ids UUID[] NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_claim_verdicts_scan_id ON claim_verdicts(scan_id);

-- Evidence artifacts table
CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    byte_offset BIGINT NOT NULL,
    byte_length BIGINT NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    context_data BYTEA,
    reproduction_script TEXT
);

CREATE INDEX idx_evidence_scan_id ON evidence_artifacts(scan_id);
CREATE INDEX idx_evidence_content_hash ON evidence_artifacts(content_hash);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(50) NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    file_path TEXT NOT NULL
);

CREATE INDEX idx_reports_scan_id ON reports(scan_id);

-- Users table (for admin dashboard)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);

-- Insert default admin user (password: admin)
INSERT INTO users (id, email, password_hash, role, created_at)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'admin@example.com',
    '$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'admin',
    NOW()
) ON CONFLICT (email) DO NOTHING;
