# seed_container_assets.py
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "vulns",
}

CONTAINERS = [
    # ── Existing ──────────────────────────────────────────────────────────────
    {
        "name": "payments-api",
        "image": "registry.example.com/payments-api:1.0.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "payments",
        "service_name": "payments-api",
        "publicly_exposed": True,
        "runs_as_root": True,
        "cves": ["CVE-2025-10001", "CVE-2025-10003"],
    },
    {
        "name": "analytics-worker",
        "image": "registry.example.com/analytics-worker:2.3.1",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "analytics",
        "service_name": "analytics-worker",
        "publicly_exposed": False,
        "runs_as_root": False,
        "cves": ["CVE-2025-10002"],
    },
    {
        "name": "frontend-web",
        "image": "registry.example.com/frontend-web:3.4.5",
        "registry": "registry.example.com",
        "environment": "staging",
        "namespace": "frontend",
        "service_name": "frontend-web",
        "publicly_exposed": True,
        "runs_as_root": False,
        "cves": [],
    },
    {
        "name": "internal-reporting-api",
        "image": "registry.example.com/internal-reporting-api:0.9.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "reporting",
        "service_name": "internal-reporting-api",
        "publicly_exposed": False,
        "runs_as_root": True,
        "cves": ["CVE-2025-10001"],
    },

    # ── New containers ─────────────────────────────────────────────────────────

    # auth-service — public, prod, root; broken access control + SSRF
    {
        "name": "auth-service",
        "image": "registry.example.com/auth-service:2.1.3",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "auth",
        "service_name": "auth-service",
        "publicly_exposed": True,
        "runs_as_root": True,
        "cves": ["CVE-2025-10005", "CVE-2025-10006"],
    },

    # user-api — public, prod, non-root; path traversal + race condition
    {
        "name": "user-api",
        "image": "registry.example.com/user-api:1.4.2",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "users",
        "service_name": "user-api",
        "publicly_exposed": True,
        "runs_as_root": False,
        "cves": ["CVE-2025-10004", "CVE-2025-10013"],
    },

    # monitoring-agent — internal, prod, root; hardcoded creds + privilege escalation
    {
        "name": "monitoring-agent",
        "image": "registry.example.com/monitoring-agent:3.0.1",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "monitoring",
        "service_name": "monitoring-agent",
        "publicly_exposed": False,
        "runs_as_root": True,
        "cves": ["CVE-2025-10007", "CVE-2025-10010"],
    },

    # media-processor — internal, prod, non-root; buffer overflow + DoS
    {
        "name": "media-processor",
        "image": "registry.example.com/media-processor:1.2.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "media",
        "service_name": "media-processor",
        "publicly_exposed": False,
        "runs_as_root": False,
        "cves": ["CVE-2025-10014", "CVE-2025-10011"],
    },

    # search-service — public, staging, non-root; reflected XSS
    {
        "name": "search-service",
        "image": "registry.example.com/search-service:0.8.5",
        "registry": "registry.example.com",
        "environment": "staging",
        "namespace": "search",
        "service_name": "search-service",
        "publicly_exposed": True,
        "runs_as_root": False,
        "cves": ["CVE-2025-10008"],
    },

    # report-generator — internal, prod, root; XXE + sensitive data exposure
    {
        "name": "report-generator",
        "image": "registry.example.com/report-generator:2.0.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "reporting",
        "service_name": "report-generator",
        "publicly_exposed": False,
        "runs_as_root": True,
        "cves": ["CVE-2025-10009", "CVE-2025-10015"],
    },

    # api-gateway — public, prod, non-root; mTLS bypass + SSRF
    {
        "name": "api-gateway",
        "image": "registry.example.com/api-gateway:4.1.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "gateway",
        "service_name": "api-gateway",
        "publicly_exposed": True,
        "runs_as_root": False,
        "cves": ["CVE-2025-10012", "CVE-2025-10006"],
    },

    # notification-worker — internal, staging, non-root; no CVEs
    {
        "name": "notification-worker",
        "image": "registry.example.com/notification-worker:1.0.4",
        "registry": "registry.example.com",
        "environment": "staging",
        "namespace": "notifications",
        "service_name": "notification-worker",
        "publicly_exposed": False,
        "runs_as_root": False,
        "cves": [],
    },

    # billing-api — public, prod, root; SQL injection + broken access control
    {
        "name": "billing-api",
        "image": "registry.example.com/billing-api:1.1.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "billing",
        "service_name": "billing-api",
        "publicly_exposed": True,
        "runs_as_root": True,
        "cves": ["CVE-2025-10001", "CVE-2025-10005"],
    },

    # config-service — internal, prod, non-root; hardcoded creds
    {
        "name": "config-service",
        "image": "registry.example.com/config-service:2.3.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "config",
        "service_name": "config-service",
        "publicly_exposed": False,
        "runs_as_root": False,
        "cves": ["CVE-2025-10007"],
    },
]


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                container_rows = [
                    (
                        c["name"],
                        c["image"],
                        c["registry"],
                        c["environment"],
                        c["namespace"],
                        c["service_name"],
                        c["publicly_exposed"],
                        c["runs_as_root"],
                    )
                    for c in CONTAINERS
                ]
 
                # Update existing rows, then insert any that don't exist yet
                for row in container_rows:
                    cur.execute(
                        """
                        UPDATE security.container_assets SET
                            image            = %s,
                            registry         = %s,
                            environment      = %s,
                            namespace        = %s,
                            service_name     = %s,
                            publicly_exposed = %s,
                            runs_as_root     = %s
                        WHERE name = %s
                        """,
                        (row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[0]),
                    )
                    if cur.rowcount == 0:
                        cur.execute(
                            """
                            INSERT INTO security.container_assets (
                                name, image, registry, environment,
                                namespace, service_name,
                                publicly_exposed, runs_as_root
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            row,
                        )
 
                cur.execute(
                    "SELECT id, name FROM security.container_assets ORDER BY id"
                )
                id_by_name = {name: cid for cid, name in cur.fetchall()}
 
                # Rebuild join table for all containers in this seed
                seeded_names = [c["name"] for c in CONTAINERS]
                seeded_ids = [id_by_name[n] for n in seeded_names if n in id_by_name]
                if seeded_ids:
                    cur.execute(
                        "DELETE FROM security.container_asset_cves WHERE container_id = ANY(%s)",
                        (seeded_ids,),
                    )
 
                join_rows = []
                for c in CONTAINERS:
                    cid = id_by_name.get(c["name"])
                    if not cid:
                        continue
                    for cve_id in c["cves"]:
                        join_rows.append((cid, cve_id))
 
                if join_rows:
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.container_asset_cves (container_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING
                        """,
                        join_rows,
                    )
 
        print("Seeded container assets and associations successfully.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()