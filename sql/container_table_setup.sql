CREATE TABLE IF NOT EXISTS security.container_assets (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    image           TEXT NOT NULL,
    registry        TEXT,
    environment     TEXT, -- e.g. prod, staging
    namespace       TEXT,
    service_name    TEXT,
    publicly_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    runs_as_root     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security.container_asset_cves (
    container_id INTEGER NOT NULL
        REFERENCES security.container_assets(id) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL
        REFERENCES security.cves(cve_id) ON DELETE CASCADE,
    PRIMARY KEY (container_id, cve_id)
);