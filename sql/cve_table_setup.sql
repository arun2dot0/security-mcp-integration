CREATE SCHEMA IF NOT EXISTS security;

CREATE TABLE IF NOT EXISTS security.cves (
    cve_id TEXT PRIMARY KEY,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score NUMERIC(3,1),
    published_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    description TEXT,
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cves_severity
    ON security.cves (severity);

CREATE INDEX IF NOT EXISTS idx_cves_published_at
    ON security.cves (published_at);

CREATE INDEX IF NOT EXISTS idx_cves_cvss_score
    ON security.cves (cvss_score);

CREATE TABLE IF NOT EXISTS security.cve_references (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES security.cves(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source TEXT,
    tags JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_cve_references_cve_id
    ON security.cve_references (cve_id);

CREATE TABLE IF NOT EXISTS security.cve_cwes (
    cve_id TEXT NOT NULL REFERENCES security.cves(cve_id) ON DELETE CASCADE,
    cwe_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, cwe_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe_id
    ON security.cve_cwes (cwe_id);