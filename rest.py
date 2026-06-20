from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from typing import Optional, List
import json

from models import ContainerAsset, CVE, AssetTag, Remediation, container_asset_tags

# --- DB setup ---
DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(
    title="Security Rest API",
    description="REST API for container assets, CVEs, asset tags, and remediations.",
    version="1.0.0",
    swagger_ui_parameters={"tryItOutEnabled": True},
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- Schema helpers ---
def cve_to_dict(c) -> dict:
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


def tag_to_dict(t) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "category": t.category,
        "description": t.description,
        "created_at": t.created_at,
    }


def remediation_to_dict(r) -> dict:
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


def get_tags_for_asset(db: Session, asset_id: int) -> List[dict]:
    rows = (
        db.execute(
            select(AssetTag)
            .join(container_asset_tags, container_asset_tags.c.tag_id == AssetTag.id)
            .where(container_asset_tags.c.container_id == asset_id)
        )
        .scalars()
        .all()
    )
    return [tag_to_dict(t) for t in rows]


def get_remediation_for_cve(db: Session, cve_id: str):
    row = db.execute(
        select(Remediation).where(Remediation.cve_id == cve_id)
    ).scalars().first()
    return remediation_to_dict(row) if row else None


def container_asset_to_dict(ca, db: Session = None) -> dict:
    payload = {
        "id": ca.id,
        "name": ca.name,
        "image": ca.image,
        "registry": ca.registry,
        "environment": ca.environment,
        "namespace": ca.namespace,
        "service_name": ca.service_name,
        "publicly_exposed": ca.publicly_exposed,
        "runs_as_root": ca.runs_as_root,
        "created_at": ca.created_at,
        "updated_at": ca.updated_at,
        "cves": [cve_to_dict(c) for c in ca.cves],
    }
    if db is not None:
        payload["tags"] = get_tags_for_asset(db, ca.id)
    return payload


# --- Routes ---

@app.get("/api/v1/container-assets", response_model=None)
def list_container_assets(
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    # Limit a subquery of asset IDs first. `cves` is lazy="joined", so limiting
    # the main query directly would cut across the JOIN-expanded rows and return
    # fewer than `limit` distinct assets.
    id_stmt = select(ContainerAsset.id)
    if publicly_exposed is not None:
        id_stmt = id_stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
    if runs_as_root is not None:
        id_stmt = id_stmt.where(ContainerAsset.runs_as_root == runs_as_root)
    id_stmt = id_stmt.limit(limit)

    stmt = select(ContainerAsset).where(ContainerAsset.id.in_(id_stmt))
    rows = db.execute(stmt).unique().scalars().all()
    return [container_asset_to_dict(row, db) for row in rows]


@app.get("/api/v1/container-assets/{asset_id}", response_model=None)
def get_container_asset(asset_id: int, db: Session = Depends(get_db)):
    row = db.get(ContainerAsset, asset_id)
    if not row:
        raise HTTPException(status_code=404, detail="Container asset not found")
    return container_asset_to_dict(row, db)


@app.get("/api/v1/container-assets/{asset_id}/tags", response_model=None)
def list_container_asset_tags(asset_id: int, db: Session = Depends(get_db)):
    row = db.get(ContainerAsset, asset_id)
    if not row:
        raise HTTPException(status_code=404, detail="Container asset not found")
    return get_tags_for_asset(db, asset_id)


@app.get("/api/v1/container-assets/{asset_id}/remediations", response_model=None)
def list_container_asset_remediations(asset_id: int, db: Session = Depends(get_db)):
    row = db.get(ContainerAsset, asset_id)
    if not row:
        raise HTTPException(status_code=404, detail="Container asset not found")

    remediations = []
    seen = set()
    for cve in row.cves:
        rem = get_remediation_for_cve(db, cve.id)
        if rem and rem["cve_id"] not in seen:
            seen.add(rem["cve_id"])
            remediations.append(rem)
    return remediations


@app.get("/api/v1/cves", response_model=None)
def list_cves(
    severity: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    stmt = select(CVE)
    if severity is not None:
        stmt = stmt.where(CVE.severity == severity.upper())

    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [cve_to_dict(c) for c in rows]


@app.get("/api/v1/cves/{cve_id}", response_model=None)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    row = db.get(CVE, cve_id)
    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")
    payload = cve_to_dict(row)
    payload["remediation"] = get_remediation_for_cve(db, cve_id)
    return payload


@app.get("/api/v1/asset-tags", response_model=None)
def list_asset_tags(
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = db.execute(select(AssetTag).limit(limit)).scalars().all()
    return [tag_to_dict(t) for t in rows]


@app.get("/api/v1/remediations", response_model=None)
def list_remediations(
    priority: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    stmt = select(Remediation)
    if priority is not None:
        stmt = stmt.where(Remediation.priority == priority.upper())

    rows = db.execute(stmt.limit(limit)).scalars().all()
    return [remediation_to_dict(r) for r in rows]


@app.get("/api/v1/remediations/{cve_id}", response_model=None)
def get_remediation(cve_id: str, db: Session = Depends(get_db)):
    row = db.execute(select(Remediation).where(Remediation.cve_id == cve_id)).scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Remediation not found")
    return remediation_to_dict(row)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("rest:app", host="127.0.0.1", port=8001, reload=True)    