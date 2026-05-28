# seed_asset_tags_remediation.py
import psycopg2
from psycopg2.extras import execute_values, Json
from datetime import datetime, timezone

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "vulns",
}

ASSET_TAGS = [
    {"name": "prod", "category": "environment", "description": "Production environment assets"},
    {"name": "staging", "category": "environment", "description": "Staging environment assets"},
    {"name": "public", "category": "exposure", "description": "Internet-facing assets"},
    {"name": "internal", "category": "exposure", "description": "Non-public internal assets"},
    {"name": "root", "category": "runtime", "description": "Container runs as root"},
    {"name": "non-root", "category": "runtime", "description": "Container does not run as root"},
    {"name": "critical", "category": "risk", "description": "High-risk critical assets"},
    {"name": "high-risk", "category": "risk", "description": "Assets with elevated security risk"},
    {"name": "payments", "category": "business", "description": "Payments domain assets"},
    {"name": "auth", "category": "business", "description": "Authentication domain assets"},
    {"name": "billing", "category": "business", "description": "Billing domain assets"},
    {"name": "reporting", "category": "business", "description": "Reporting domain assets"},
    {"name": "gateway", "category": "business", "description": "API gateway assets"},
    {"name": "media", "category": "business", "description": "Media processing assets"},
]

ASSET_TAG_MAP = {
    "payments-api": ["prod", "public", "root", "critical", "payments", "high-risk"],
    "analytics-worker": ["prod", "internal", "non-root"],
    "frontend-web": ["staging", "public", "non-root"],
    "internal-reporting-api": ["prod", "internal", "root", "reporting", "high-risk"],
    "auth-service": ["prod", "public", "root", "critical", "auth", "high-risk"],
    "user-api": ["prod", "public", "non-root", "critical"],
    "monitoring-agent": ["prod", "internal", "root", "high-risk"],
    "media-processor": ["prod", "internal", "non-root", "media"],
    "search-service": ["staging", "public", "non-root"],
    "report-generator": ["prod", "internal", "root", "reporting", "high-risk"],
    "api-gateway": ["prod", "public", "non-root", "gateway", "critical"],
    "notification-worker": ["staging", "internal", "non-root"],
    "billing-api": ["prod", "public", "root", "critical", "billing", "high-risk"],
    "config-service": ["prod", "internal", "non-root"],
}

REMEDIATIONS = [
    {
        "cve_id": "CVE-2025-10001",
        "title": "Patch SQL injection in admin search endpoint",
        "priority": "HIGH",
        "summary": "Upgrade to the patched release and validate all user input in search filters.",
        "fix_steps": [
            "Apply the vendor patch.",
            "Use parameterized queries.",
            "Add input validation and server-side allowlists.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10001",
            "https://example.com/patch-10001",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10002",
        "title": "Fix reflected XSS in comment renderer",
        "priority": "MEDIUM",
        "summary": "Escape output and sanitize HTML before rendering comments.",
        "fix_steps": [
            "Escape all user-controlled output.",
            "Sanitize HTML with an approved library.",
            "Add CSP headers.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10002",
        ],
        "estimated_effort": "Small",
    },
    {
        "cve_id": "CVE-2025-10003",
        "title": "Prevent insecure deserialization",
        "priority": "CRITICAL",
        "summary": "Reject untrusted serialized payloads and replace with safe formats.",
        "fix_steps": [
            "Remove unsafe deserialization paths.",
            "Use JSON or a typed safe format.",
            "Validate all payload sources.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10003",
        ],
        "estimated_effort": "Large",
    },
    {
        "cve_id": "CVE-2025-10004",
        "title": "Fix path traversal in upload handler",
        "priority": "HIGH",
        "summary": "Normalize file paths and block traversal sequences.",
        "fix_steps": [
            "Canonicalize user-supplied paths.",
            "Reject ../ sequences.",
            "Store uploads outside web roots.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10004",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10005",
        "title": "Fix broken access control",
        "priority": "CRITICAL",
        "summary": "Enforce authorization checks on every sensitive API route.",
        "fix_steps": [
            "Add server-side authZ checks.",
            "Deny-by-default on sensitive endpoints.",
            "Add tests for privilege escalation paths.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10005",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10006",
        "title": "Mitigate SSRF in outbound fetch logic",
        "priority": "HIGH",
        "summary": "Restrict outbound destinations and block internal address ranges.",
        "fix_steps": [
            "Allowlist approved destinations.",
            "Block link-local and internal IP ranges.",
            "Validate URLs before fetch.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10006",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10007",
        "title": "Rotate hardcoded credentials",
        "priority": "HIGH",
        "summary": "Remove embedded secrets and replace them with managed secret storage.",
        "fix_steps": [
            "Rotate exposed credentials.",
            "Move secrets to a vault or secret manager.",
            "Scan images for embedded secrets.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10007",
        ],
        "estimated_effort": "Small",
    },
    {
        "cve_id": "CVE-2025-10008",
        "title": "Prevent reflected XSS in search endpoint",
        "priority": "MEDIUM",
        "summary": "Escape output and sanitize search results before returning HTML.",
        "fix_steps": [
            "Escape all reflected output.",
            "Sanitize HTML fragments.",
            "Add CSP protections.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10008",
        ],
        "estimated_effort": "Small",
    },
    {
        "cve_id": "CVE-2025-10009",
        "title": "Block XXE in XML report parser",
        "priority": "HIGH",
        "summary": "Disable external entity processing in XML parsers.",
        "fix_steps": [
            "Disable DTD and external entity expansion.",
            "Use secure XML parser defaults.",
            "Validate input content types.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10009",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10010",
        "title": "Reduce privilege escalation risk",
        "priority": "HIGH",
        "summary": "Drop unnecessary capabilities and remove privileged container settings.",
        "fix_steps": [
            "Run as non-root.",
            "Drop Linux capabilities.",
            "Use a restrictive security context.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10010",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10011",
        "title": "Patch denial of service in media parser",
        "priority": "MEDIUM",
        "summary": "Upgrade parser libraries and add request size limits.",
        "fix_steps": [
            "Patch parser dependencies.",
            "Add input size limits.",
            "Rate-limit expensive processing.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10011",
        ],
        "estimated_effort": "Small",
    },
    {
        "cve_id": "CVE-2025-10012",
        "title": "Fix mTLS bypass in gateway",
        "priority": "CRITICAL",
        "summary": "Enforce certificate validation on all upstream routes.",
        "fix_steps": [
            "Validate client certificates consistently.",
            "Reject unauthenticated upstream calls.",
            "Test all proxy bypass paths.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10012",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10013",
        "title": "Fix race condition in user creation flow",
        "priority": "MEDIUM",
        "summary": "Serialize conflicting writes and add locking where needed.",
        "fix_steps": [
            "Add transaction boundaries.",
            "Use locking on duplicate-sensitive operations.",
            "Add concurrency tests.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10013",
        ],
        "estimated_effort": "Medium",
    },
    {
        "cve_id": "CVE-2025-10014",
        "title": "Patch buffer overflow in image library",
        "priority": "CRITICAL",
        "summary": "Upgrade the image processing library and validate file inputs.",
        "fix_steps": [
            "Apply the patched library version.",
            "Validate image formats before parsing.",
            "Run processing in a sandbox.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10014",
            "https://example.com/patch-10014",
        ],
        "estimated_effort": "Large",
    },
    {
        "cve_id": "CVE-2025-10015",
        "title": "Remove sensitive data from debug logs",
        "priority": "LOW",
        "summary": "Disable verbose logging and scrub secret values from logs.",
        "fix_steps": [
            "Disable debug mode in production.",
            "Redact secrets and tokens.",
            "Add log filtering rules.",
        ],
        "vendor_references": [
            "https://example.com/advisory-10015",
        ],
        "estimated_effort": "Small",
    },
]

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS security.asset_tags (
                        id SERIAL PRIMARY KEY,
                        name TEXT UNIQUE NOT NULL,
                        category TEXT NOT NULL,
                        description TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS security.container_asset_tags (
                        container_id INT NOT NULL REFERENCES security.container_assets(id) ON DELETE CASCADE,
                        tag_id INT NOT NULL REFERENCES security.asset_tags(id) ON DELETE CASCADE,
                        PRIMARY KEY (container_id, tag_id)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS security.remediations (
                        id SERIAL PRIMARY KEY,
                        cve_id TEXT NOT NULL REFERENCES security.cves(cve_id) ON DELETE CASCADE,
                        title TEXT NOT NULL,
                        priority TEXT NOT NULL,
                        summary TEXT,
                        fix_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
                        vendor_references JSONB NOT NULL DEFAULT '[]'::jsonb,
                        estimated_effort TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)

                for tag in ASSET_TAGS:
                    cur.execute(
                        """
                        INSERT INTO security.asset_tags (name, category, description)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (name) DO UPDATE SET
                            category = EXCLUDED.category,
                            description = EXCLUDED.description
                        """,
                        (tag["name"], tag["category"], tag["description"]),
                    )

                cur.execute("SELECT id, name FROM security.asset_tags")
                tag_id_by_name = {name: tid for tid, name in cur.fetchall()}

                cur.execute("SELECT id, name FROM security.container_assets")
                container_id_by_name = {name: cid for cid, name in cur.fetchall()}

                cur.execute("DELETE FROM security.container_asset_tags")
                join_rows = []
                for asset_name, tags in ASSET_TAG_MAP.items():
                    cid = container_id_by_name.get(asset_name)
                    if not cid:
                        continue
                    for tag_name in tags:
                        tid = tag_id_by_name.get(tag_name)
                        if tid:
                            join_rows.append((cid, tid))

                if join_rows:
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.container_asset_tags (container_id, tag_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING
                        """,
                        join_rows,
                    )

                cur.execute("DELETE FROM security.remediations")
                remediation_rows = [
                    (
                        r["cve_id"],
                        r["title"],
                        r["priority"],
                        r["summary"],
                        Json(r["fix_steps"]),
                        Json(r["vendor_references"]),
                        r["estimated_effort"],
                    )
                    for r in REMEDIATIONS
                ]
                execute_values(
                    cur,
                    """
                    INSERT INTO security.remediations
                    (cve_id, title, priority, summary, fix_steps, vendor_references, estimated_effort)
                    VALUES %s
                    """,
                    remediation_rows,
                )

        print("Seeded asset tags and remediations successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()