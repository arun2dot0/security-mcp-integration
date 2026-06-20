from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, select
from typing import Optional
from mcp.server.fastmcp import FastMCP

from models import ContainerAsset, CVE, AssetTag, Remediation, container_asset_tags

DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

mcp = FastMCP("Security Rest API", host="127.0.0.1", port=8001)


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

def get_tags_for_assets(db: Session, asset_ids):
    """Load tags for many assets in a single query, grouped by asset id."""
    if not asset_ids:
        return {}
    rows = db.execute(
        select(container_asset_tags.c.container_id, AssetTag)
        .join(AssetTag, container_asset_tags.c.tag_id == AssetTag.id)
        .where(container_asset_tags.c.container_id.in_(asset_ids))
    ).all()
    grouped: dict = {aid: [] for aid in asset_ids}
    for container_id, tag in rows:
        grouped.setdefault(container_id, []).append(serialize_tag(tag))
    return grouped

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
        # Limit a subquery of asset IDs first. `cves` is lazy="joined", so
        # limiting the main query directly would cut across the JOIN-expanded
        # rows and return fewer than `limit` distinct assets.
        id_stmt = select(ContainerAsset.id)
        if publicly_exposed is not None:
            id_stmt = id_stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
        if runs_as_root is not None:
            id_stmt = id_stmt.where(ContainerAsset.runs_as_root == runs_as_root)
        id_stmt = id_stmt.limit(limit)

        stmt = select(ContainerAsset).where(ContainerAsset.id.in_(id_stmt))
        rows = db.execute(stmt).unique().scalars().all()

        tags_by_asset = get_tags_for_assets(db, [row.id for row in rows])
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
                "tags": tags_by_asset.get(row.id, []),
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
