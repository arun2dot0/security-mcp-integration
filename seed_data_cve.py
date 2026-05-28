import json
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "vulns",
}

CVES = [
    # ── Existing ──────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2025-10001",
        "summary": "SQL injection in admin search endpoint.",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "published_at": "2025-01-12T10:15:00Z",
        "updated_at": "2025-01-15T09:00:00Z",
        "description": "Improper input validation allows SQL injection in the admin search endpoint.",
        "references": [
            {"url": "https://example.com/advisory-10001", "source": "vendor", "tags": ["advisory"]},
            {"url": "https://example.com/patch-10001", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-89"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
        },
    },
    {
        "cve_id": "CVE-2025-10002",
        "summary": "Cross-site scripting in comment renderer.",
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "published_at": "2025-02-20T14:30:00Z",
        "updated_at": "2025-02-22T08:20:00Z",
        "description": "Unsanitized HTML is reflected in the comment rendering pipeline.",
        "references": [
            {"url": "https://example.com/advisory-10002", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-79"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "LOW", "integrity": "LOW", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10003",
        "summary": "Insecure deserialization in job worker.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "published_at": "2025-03-05T16:45:00Z",
        "updated_at": "2025-03-06T11:10:00Z",
        "description": "Untrusted serialized payloads can trigger remote code execution.",
        "references": [
            {"url": "https://example.com/advisory-10003", "source": "research", "tags": ["analysis"]},
        ],
        "cwes": ["CWE-502"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
        },
    },

    # ── New CVEs ──────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2025-10004",
        "summary": "Path traversal in file download API.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "published_at": "2025-04-01T08:00:00Z",
        "updated_at": "2025-04-03T12:00:00Z",
        "description": "Insufficient path sanitization allows attackers to read arbitrary files outside the intended directory.",
        "references": [
            {"url": "https://example.com/advisory-10004", "source": "vendor", "tags": ["advisory"]},
            {"url": "https://example.com/patch-10004", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-22"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "NONE", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10005",
        "summary": "Broken access control in user management API.",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "published_at": "2025-04-10T09:30:00Z",
        "updated_at": "2025-04-11T14:00:00Z",
        "description": "Missing authorization checks allow unprivileged users to modify or delete other users' accounts.",
        "references": [
            {"url": "https://example.com/advisory-10005", "source": "research", "tags": ["analysis"]},
            {"url": "https://example.com/patch-10005", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-284"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
        },
    },
    {
        "cve_id": "CVE-2025-10006",
        "summary": "Server-side request forgery in webhook handler.",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "published_at": "2025-04-18T11:00:00Z",
        "updated_at": "2025-04-20T09:45:00Z",
        "description": "The webhook URL parameter is not validated, allowing SSRF attacks against internal services.",
        "references": [
            {"url": "https://example.com/advisory-10006", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-918"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "LOW", "availability": "LOW"},
        },
    },
    {
        "cve_id": "CVE-2025-10007",
        "summary": "Hardcoded credentials in monitoring agent.",
        "severity": "CRITICAL",
        "cvss_score": 9.4,
        "published_at": "2025-05-02T07:15:00Z",
        "updated_at": "2025-05-03T10:30:00Z",
        "description": "A hardcoded admin password is present in the monitoring agent binary, granting full access to the metrics API.",
        "references": [
            {"url": "https://example.com/advisory-10007", "source": "research", "tags": ["analysis", "exploit"]},
        ],
        "cwes": ["CWE-798"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
        },
    },
    {
        "cve_id": "CVE-2025-10008",
        "summary": "Reflected XSS in search results page.",
        "severity": "MEDIUM",
        "cvss_score": 5.4,
        "published_at": "2025-05-08T13:00:00Z",
        "updated_at": "2025-05-09T08:00:00Z",
        "description": "User-supplied query parameters are reflected unsanitized in search result pages.",
        "references": [
            {"url": "https://example.com/advisory-10008", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-79"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "LOW", "integrity": "LOW", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10009",
        "summary": "XML external entity injection in report parser.",
        "severity": "HIGH",
        "cvss_score": 7.9,
        "published_at": "2025-05-14T10:00:00Z",
        "updated_at": "2025-05-15T11:30:00Z",
        "description": "The report parser processes external XML entities, enabling data exfiltration and SSRF via XXE.",
        "references": [
            {"url": "https://example.com/advisory-10009", "source": "research", "tags": ["analysis"]},
            {"url": "https://example.com/patch-10009", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-611"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "LOW", "availability": "LOW"},
        },
    },
    {
        "cve_id": "CVE-2025-10010",
        "summary": "Privilege escalation via misconfigured sudo rules.",
        "severity": "CRITICAL",
        "cvss_score": 9.3,
        "published_at": "2025-05-20T15:00:00Z",
        "updated_at": "2025-05-21T09:00:00Z",
        "description": "Overly permissive sudo rules allow low-privileged container processes to execute arbitrary commands as root.",
        "references": [
            {"url": "https://example.com/advisory-10010", "source": "research", "tags": ["analysis", "exploit"]},
        ],
        "cwes": ["CWE-269"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
        },
    },
    {
        "cve_id": "CVE-2025-10011",
        "summary": "Denial of service via malformed gzip payload.",
        "severity": "MEDIUM",
        "cvss_score": 5.9,
        "published_at": "2025-03-25T12:00:00Z",
        "updated_at": "2025-03-26T08:00:00Z",
        "description": "A crafted gzip payload causes unbounded memory allocation, resulting in service crash.",
        "references": [
            {"url": "https://example.com/advisory-10011", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-400"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "NONE", "integrity": "NONE", "availability": "HIGH"},
        },
    },
    {
        "cve_id": "CVE-2025-10012",
        "summary": "Improper certificate validation in mTLS client.",
        "severity": "HIGH",
        "cvss_score": 7.4,
        "published_at": "2025-02-05T09:00:00Z",
        "updated_at": "2025-02-07T14:30:00Z",
        "description": "The mTLS client skips hostname verification, enabling man-in-the-middle attacks on internal service calls.",
        "references": [
            {"url": "https://example.com/advisory-10012", "source": "vendor", "tags": ["advisory", "patch"]},
        ],
        "cwes": ["CWE-295"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10013",
        "summary": "Race condition in session token generation.",
        "severity": "MEDIUM",
        "cvss_score": 6.8,
        "published_at": "2025-01-28T16:00:00Z",
        "updated_at": "2025-01-30T10:00:00Z",
        "description": "A TOCTOU race condition in the session token generator can result in token collisions and session hijacking.",
        "references": [
            {"url": "https://example.com/advisory-10013", "source": "research", "tags": ["analysis"]},
        ],
        "cwes": ["CWE-362"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "LOW", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10014",
        "summary": "Buffer overflow in image processing library.",
        "severity": "CRITICAL",
        "cvss_score": 9.6,
        "published_at": "2025-05-18T08:30:00Z",
        "updated_at": "2025-05-19T12:00:00Z",
        "description": "A heap buffer overflow in the bundled image processing library can be triggered via a crafted TIFF file, leading to remote code execution.",
        "references": [
            {"url": "https://example.com/advisory-10014", "source": "research", "tags": ["analysis", "exploit"]},
            {"url": "https://example.com/patch-10014", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-122"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
        },
    },
    {
        "cve_id": "CVE-2025-10015",
        "summary": "Sensitive data exposure in debug logging.",
        "severity": "LOW",
        "cvss_score": 3.5,
        "published_at": "2025-04-25T07:00:00Z",
        "updated_at": "2025-04-26T09:00:00Z",
        "description": "Debug log output includes plaintext API keys and user tokens when verbose logging is enabled.",
        "references": [
            {"url": "https://example.com/advisory-10015", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-532"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "LOW", "integrity": "NONE", "availability": "NONE"},
        },
    },
]


def iso_to_dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                for cve in CVES:
                    cur.execute(
                        """
                        INSERT INTO security.cves (
                            cve_id, summary, severity, cvss_score,
                            published_at, updated_at, description, raw_data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            summary      = EXCLUDED.summary,
                            severity     = EXCLUDED.severity,
                            cvss_score   = EXCLUDED.cvss_score,
                            published_at = EXCLUDED.published_at,
                            updated_at   = EXCLUDED.updated_at,
                            description  = EXCLUDED.description,
                            raw_data     = EXCLUDED.raw_data,
                            modified_at  = NOW()
                        """,
                        (
                            cve["cve_id"],
                            cve["summary"],
                            cve["severity"],
                            cve["cvss_score"],
                            iso_to_dt(cve["published_at"]),
                            iso_to_dt(cve["updated_at"]),
                            cve["description"],
                            Json(cve["raw_data"]),
                        ),
                    )

                    cur.execute(
                        "DELETE FROM security.cve_references WHERE cve_id = %s",
                        (cve["cve_id"],),
                    )
                    ref_rows = [
                        (
                            cve["cve_id"],
                            ref["url"],
                            ref.get("source"),
                            Json(ref.get("tags", [])),
                        )
                        for ref in cve["references"]
                    ]
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.cve_references (cve_id, url, source, tags)
                        VALUES %s
                        """,
                        ref_rows,
                    )

                    cur.execute(
                        "DELETE FROM security.cve_cwes WHERE cve_id = %s",
                        (cve["cve_id"],),
                    )
                    cwe_rows = [(cve["cve_id"], cwe) for cwe in cve["cwes"]]
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.cve_cwes (cve_id, cwe_id)
                        VALUES %s
                        """,
                        cwe_rows,
                    )

        print("Seed data inserted successfully.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()