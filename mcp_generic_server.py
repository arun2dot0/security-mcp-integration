from fastapi import FastAPI, Depends, Query
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, select
from typing import Optional
from mcp.server.fastmcp import FastMCP

from models import ContainerAsset, CVE, AssetTag, Remediation, container_asset_tags

DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="Security Rest API")
mcp = FastMCP("Security Rest API", host="127.0.0.1", port=8001)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def serialize_cve(c):
    return {
        "cve_id": c.id,
        "summary": c.summary,
        "severity": c.severity,
        "cvss_score": float(c.cvss_score) if c.cvss_score is not None else None,
        "published_at": c.published_at,
        "updated_at": c.updated_at,
        "description": c.description,
        "raw_data": c.raw_data,
    }

def serialize_tag(t):
    return {
        "id": t.id,
        "name": t.name,
        "category": t.category,
        "description": t.description,
        "created_at": t.created_at,
    }

def serialize_remediation(r):
    return {
        "id": r.id,
        "cve_id": r.cve_id,
        "title": r.title,
        "priority": r.priority,
        "summary": r.summary,
        "fix_steps": r.fix_steps,
        "vendor_references": r.vendor_references,
        "estimated_effort": r.estimated_effort,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
    }

def get_tags_for_asset(db: Session, asset_id: int):
    rows = (
        db.execute(
            select(AssetTag)
            .join(container_asset_tags, container_asset_tags.c.tag_id == AssetTag.id)
            .where(container_asset_tags.c.container_id == asset_id)
        )
        .scalars()
        .all()
    )
    return [serialize_tag(t) for t in rows]

def get_remediation_for_cve(db: Session, cve_id: str):
    row = db.execute(
        select(Remediation).where(Remediation.cve_id == cve_id)
    ).scalars().first()
    return serialize_remediation(row) if row else None

@app.get("/api/v1/container-assets")
def list_container_assets_http(
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    stmt = select(ContainerAsset)
    if publicly_exposed is not None:
        stmt = stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
    if runs_as_root is not None:
        stmt = stmt.where(ContainerAsset.runs_as_root == runs_as_root)

    rows = db.execute(stmt.limit(limit)).unique().scalars().all()
    return [
        {
            "id": row.id,
            "name": row.name,
            "image": row.image,
            "registry": row.registry,
            "environment": row.environment,
            "namespace": row.namespace,
            "service_name": row.service_name,
            "publicly_exposed": row.publicly_exposed,
            "runs_as_root": row.runs_as_root,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "tags": get_tags_for_asset(db, row.id),
            "cves": [serialize_cve(c) for c in row.cves],
        }
        for row in rows
    ]

@app.get("/api/v1/container-assets/{asset_id}/tags")
def list_asset_tags_http(asset_id: int, db: Session = Depends(get_db)):
    return get_tags_for_asset(db, asset_id)

@app.get("/api/v1/container-assets/{asset_id}/remediations")
def list_asset_remediations_http(asset_id: int, db: Session = Depends(get_db)):
    row = db.get(ContainerAsset, asset_id)
    if not row:
        return []
    result = []
    for c in row.cves:
        rem = get_remediation_for_cve(db, c.id)
        if rem:
            result.append(rem)
    return result

@app.get("/api/v1/cves")
def list_cves_http(
    severity: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    stmt = select(CVE)
    if severity is not None:
        stmt = stmt.where(CVE.severity == severity.upper())

    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [serialize_cve(c) for c in rows]

@app.get("/api/v1/cves/{cve_id}")
def get_cve_http(cve_id: str, db: Session = Depends(get_db)):
    row = db.get(CVE, cve_id)
    if not row:
        return None
    payload = serialize_cve(row)
    payload["remediation"] = get_remediation_for_cve(db, cve_id)
    return payload

@app.get("/api/v1/asset-tags")
def list_asset_tags_http(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.execute(select(AssetTag).limit(limit)).scalars().all()
    return [serialize_tag(t) for t in rows]

@app.get("/api/v1/remediations")
def list_remediations_http(
    priority: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    stmt = select(Remediation)
    if priority is not None:
        stmt = stmt.where(Remediation.priority == priority.upper())
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [serialize_remediation(r) for r in rows]

@app.get("/api/v1/remediations/{cve_id}")
def get_remediation_http(cve_id: str, db: Session = Depends(get_db)):
    return get_remediation_for_cve(db, cve_id)

@mcp.tool()
def list_container_assets(
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    limit: int = 20,
):
    """
    Query the REST Security API for container assets, tags, and embedded CVEs.

    Use this tool for broad inventory retrieval when you want the REST payload shape,
    including nested CVEs and asset tags. This is useful for comparison against GraphQL,
    where the same information can often be selected more precisely in one query.

    Parameters:
    - publicly_exposed: Filter to exposed assets only.
    - runs_as_root: Filter to assets running as root.
    - limit: Maximum number of assets to return.
    """
    db = SessionLocal()
    try:
        stmt = select(ContainerAsset)
        if publicly_exposed is not None:
            stmt = stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
        if runs_as_root is not None:
            stmt = stmt.where(ContainerAsset.runs_as_root == runs_as_root)

        rows = db.execute(stmt.limit(limit)).unique().scalars().all()
        return [
            {
                "id": row.id,
                "name": row.name,
                "image": row.image,
                "registry": row.registry,
                "environment": row.environment,
                "namespace": row.namespace,
                "service_name": row.service_name,
                "publicly_exposed": row.publicly_exposed,
                "runs_as_root": row.runs_as_root,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "tags": get_tags_for_asset(db, row.id),
                "cves": [serialize_cve(c) for c in row.cves],
            }
            for row in rows
        ]
    finally:
        db.close()

@mcp.tool()
def list_cves(severity: Optional[str] = None, limit: int = 20):
    """
    Query the REST Security API for CVEs by severity.

    Use this tool when you want a broad vulnerability list from the REST API.
    Use the GraphQL integration instead when you want nested tags or remediation in one call.

    Parameters:
    - severity: Optional severity filter such as LOW, MEDIUM, HIGH, or CRITICAL.
    - limit: Maximum number of CVEs to return.
    """
    db = SessionLocal()
    try:
        stmt = select(CVE)
        if severity is not None:
            stmt = stmt.where(CVE.severity == severity.upper())

        rows = db.execute(stmt.limit(limit)).scalars().all()
        return [serialize_cve(c) for c in rows]
    finally:
        db.close()

@mcp.tool()
def list_asset_tags(limit: int = 100):
    """
    Query the REST Security API for asset tags.

    Use this tool when you need tag inventory such as prod, staging, public, internal,
    critical, or business-domain tags.
    """
    db = SessionLocal()
    try:
        rows = db.execute(select(AssetTag).limit(limit)).scalars().all()
        return [serialize_tag(t) for t in rows]
    finally:
        db.close()

@mcp.tool()
def list_remediations(priority: Optional[str] = None, limit: int = 100):
    """
    Query the REST Security API for remediation guidance linked to CVEs.

    Use this tool when you want fix guidance, patch recommendations, or remediation summaries.
    """
    db = SessionLocal()
    try:
        stmt = select(Remediation)
        if priority is not None:
            stmt = stmt.where(Remediation.priority == priority.upper())
        rows = db.execute(stmt.limit(limit)).scalars().all()
        return [serialize_remediation(r) for r in rows]
    finally:
        db.close()

if __name__ == "__main__":
    mcp.run(transport="streamable-http", mount_path="/mcp")
    # mcp.run(transport="stdio")