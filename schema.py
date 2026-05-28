import sys
import json
import logging
from datetime import datetime
from typing import List, Optional

import strawberry
from strawberry.extensions import SchemaExtension
from strawberry.scalars import JSON

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from models import CVE, ContainerAsset, AssetTag, Remediation, container_asset_tags

logger = logging.getLogger("mcp")

DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


class ClaudeQueryLogger(SchemaExtension):
    """Custom Strawberry extension to capture exactly what Claude executes."""

    def on_execute(self):
        execution_context = self.execution_context
        log_msg = (
            f"\n📥 [RAW GRAPHQL RECEIVED FROM LLM]\n"
            f"{execution_context.query.strip()}\n"
        )
        if execution_context.variables:
            log_msg += f"Variables: {json.dumps(execution_context.variables, indent=2)}\n"
        logger.info(log_msg)
        yield


@strawberry.type
class AssetTagType:
    id: int
    name: str
    category: str
    description: Optional[str]
    created_at: Optional[datetime]


@strawberry.type
class RemediationType:
    id: int
    cve_id: str
    title: str
    priority: str
    summary: Optional[str]
    fix_steps: JSON
    vendor_references: JSON
    estimated_effort: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


@strawberry.type
class CVEType:
    id: str
    summary: str
    severity: str
    cvss_score: Optional[float]
    published_at: Optional[datetime]
    updated_at: Optional[datetime]
    description: Optional[str]
    raw_data: Optional[JSON]

    @strawberry.field
    def references(self) -> JSON:
        return (self.raw_data or {}).get("references", [])

    @strawberry.field
    def remediation(self) -> Optional[RemediationType]:
        with SessionLocal() as session:
            row = session.execute(
                select(Remediation).where(Remediation.cve_id == self.id)
            ).scalars().first()

            if not row:
                return None

            return RemediationType(
                id=row.id,
                cve_id=row.cve_id,
                title=row.title,
                priority=row.priority,
                summary=row.summary,
                fix_steps=row.fix_steps,
                vendor_references=row.vendor_references,
                estimated_effort=row.estimated_effort,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )


def get_tags_for_asset(session, asset_id: int) -> List[AssetTagType]:
    rows = (
        session.execute(
            select(AssetTag)
            .join(container_asset_tags, container_asset_tags.c.tag_id == AssetTag.id)
            .where(container_asset_tags.c.container_id == asset_id)
        )
        .scalars()
        .all()
    )

    return [
        AssetTagType(
            id=row.id,
            name=row.name,
            category=row.category,
            description=row.description,
            created_at=row.created_at,
        )
        for row in rows
    ]


@strawberry.type
class ContainerAssetType:
    id: int
    name: str
    image: str
    registry: Optional[str]
    environment: Optional[str]
    namespace: Optional[str]
    service_name: Optional[str]
    publicly_exposed: bool
    runs_as_root: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    cves: List[CVEType]
    tags: List[AssetTagType]


@strawberry.type
class Query:
    @strawberry.field
    def cves(
        self,
        severity: Optional[str] = None,
        limit: int = 20,
        published_after: Optional[datetime] = None,
        published_before: Optional[datetime] = None,
    ) -> List[CVEType]:
        with SessionLocal() as session:
            stmt = select(CVE)

            if severity:
                stmt = stmt.where(CVE.severity == severity)
            if published_after:
                stmt = stmt.where(CVE.published_at >= published_after)
            if published_before:
                stmt = stmt.where(CVE.published_at <= published_before)

            rows = session.execute(stmt.limit(limit)).scalars().all()

            return [
                CVEType(
                    id=row.id,
                    summary=row.summary,
                    severity=row.severity,
                    cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
                    published_at=row.published_at,
                    updated_at=row.updated_at,
                    description=row.description,
                    raw_data=row.raw_data,
                )
                for row in rows
            ]

    @strawberry.field
    def cve(self, id: str) -> Optional[CVEType]:
        with SessionLocal() as session:
            row = session.get(CVE, id)
            if not row:
                return None

            return CVEType(
                id=row.id,
                summary=row.summary,
                severity=row.severity,
                cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
                published_at=row.published_at,
                updated_at=row.updated_at,
                description=row.description,
                raw_data=row.raw_data,
            )

    @strawberry.field
    def container_assets(
        self,
        publicly_exposed: Optional[bool] = None,
        runs_as_root: Optional[bool] = None,
        environment: Optional[str] = None,
        namespace: Optional[str] = None,
        service_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        limit: int = 20,
    ) -> List[ContainerAssetType]:
        with SessionLocal() as session:
            stmt = select(ContainerAsset)
            if environment:
                stmt = stmt.where(ContainerAsset.environment == environment)

            if namespace:
                stmt = stmt.where(ContainerAsset.namespace == namespace)
            if created_after:
                stmt = stmt.where(ContainerAsset.created_at >= created_after)

            if created_before:
                stmt = stmt.where(ContainerAsset.created_at <= created_before)
            if service_name:
                stmt = stmt.where(ContainerAsset.service_name == service_name)
            if publicly_exposed is not None:
                stmt = stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
            if runs_as_root is not None:
                stmt = stmt.where(ContainerAsset.runs_as_root == runs_as_root)

            # Filter by tag names if provided
            if tags:
                stmt = (
                    stmt.join(
                        container_asset_tags,
                        ContainerAsset.id == container_asset_tags.c.container_id,
                    )
                    .join(
                        AssetTag,
                        container_asset_tags.c.tag_id == AssetTag.id,
                    )
                    .where(AssetTag.name.in_(tags))
                    .distinct()
                )

            result = session.execute(stmt.limit(limit))
            rows = result.unique().scalars().all()

            return [
                ContainerAssetType(
                    id=row.id,
                    name=row.name,
                    image=row.image,
                    registry=row.registry,
                    environment=row.environment,
                    namespace=row.namespace,
                    service_name=row.service_name,
                    publicly_exposed=row.publicly_exposed,
                    runs_as_root=row.runs_as_root,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                    cves=[
                        CVEType(
                            id=cve.id,
                            summary=cve.summary,
                            severity=cve.severity,
                            cvss_score=float(cve.cvss_score)
                            if cve.cvss_score is not None
                            else None,
                            published_at=cve.published_at,
                            updated_at=cve.updated_at,
                            description=cve.description,
                            raw_data=cve.raw_data,
                        )
                        for cve in row.cves
                    ],
                    tags=get_tags_for_asset(session, row.id),
                )
                for row in rows
            ]

    @strawberry.field
    def container_asset(self, id: int) -> Optional[ContainerAssetType]:
        with SessionLocal() as session:
            row = session.get(ContainerAsset, id)
            if not row:
                return None

            return ContainerAssetType(
                id=row.id,
                name=row.name,
                image=row.image,
                registry=row.registry,
                environment=row.environment,
                namespace=row.namespace,
                service_name=row.service_name,
                publicly_exposed=row.publicly_exposed,
                runs_as_root=row.runs_as_root,
                created_at=row.created_at,
                updated_at=row.updated_at,
                cves=[
                    CVEType(
                        id=cve.id,
                        summary=cve.summary,
                        severity=cve.severity,
                        cvss_score=float(cve.cvss_score) if cve.cvss_score is not None else None,
                        published_at=cve.published_at,
                        updated_at=cve.updated_at,
                        description=cve.description,
                        raw_data=cve.raw_data,
                    )
                    for cve in row.cves
                ],
                tags=get_tags_for_asset(session, row.id),
            )

    @strawberry.field
    def asset_tags(self, limit: int = 100) -> List[AssetTagType]:
        with SessionLocal() as session:
            rows = session.execute(select(AssetTag).limit(limit)).scalars().all()
            return [
                AssetTagType(
                    id=row.id,
                    name=row.name,
                    category=row.category,
                    description=row.description,
                    created_at=row.created_at,
                )
                for row in rows
            ]

    @strawberry.field
    def remediations(self, priority: Optional[str] = None, limit: int = 100) -> List[RemediationType]:
        with SessionLocal() as session:
            stmt = select(Remediation)
            if priority:
                stmt = stmt.where(Remediation.priority == priority)

            rows = session.execute(stmt.limit(limit)).scalars().all()
            return [
                RemediationType(
                    id=row.id,
                    cve_id=row.cve_id,
                    title=row.title,
                    priority=row.priority,
                    summary=row.summary,
                    fix_steps=row.fix_steps,
                    vendor_references=row.vendor_references,
                    estimated_effort=row.estimated_effort,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
                for row in rows
            ]


schema = strawberry.Schema(query=Query, extensions=[ClaudeQueryLogger])