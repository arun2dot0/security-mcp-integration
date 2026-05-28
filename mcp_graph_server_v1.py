import sys
import json
from typing import List,Optional
from mcp.server.fastmcp import FastMCP
from strawberry.extensions import SchemaExtension
from schema import schema


ALL_CONTAINER_FIELDS = {
    "id",
    "name",
    "image",
    "registry",
    "environment",
    "namespace",
    "serviceName",
    "publiclyExposed",
    "runsAsRoot",
    "createdAt",
    "updatedAt",
}

def build_container_selection(fields: Optional[List[str]]) -> str:
    """
    Build the GraphQL selection set for containerAssets based on requested fields.
    Falls back to ALL_CONTAINER_FIELDS if fields is None or empty.
    """
    if not fields:
        selected = ALL_CONTAINER_FIELDS
    else:
        # Normalize "container.name" -> "name" and intersect with allowed set
        selected = {f.split(".")[-1] for f in fields} & ALL_CONTAINER_FIELDS

        # If nothing survived the intersection, fall back to ALL_CONTAINER_FIELDS
        if not selected:
            selected = ALL_CONTAINER_FIELDS

    lines = [f"            {field}" for field in sorted(selected)]
    return "\n".join(lines)

mcp = FastMCP("Security API GraphQL", host="127.0.0.1", port=8000)

class ClaudeQueryLogger(SchemaExtension):
    """Log each GraphQL query executed through the schema."""
    def on_execute(self):
        execution_context = self.execution_context
        print("\n" + "═" * 60, file=sys.stderr)
        print("📥 RAW GRAPHQL RECEIVED FROM LLM:", file=sys.stderr)
        print(execution_context.query, file=sys.stderr)
        if execution_context.variables:
            print(
                f"Variables: {json.dumps(execution_context.variables, indent=2)}",
                file=sys.stderr,
            )
        print("═" * 60 + "\n", file=sys.stderr)
        sys.stderr.flush()
        yield

def execute_gql_with_logging(gql_query: str, variables: dict):
    return schema.execute_sync(gql_query, variable_values=variables)

@mcp.tool()
def get_cves(
    severity: Optional[str] = None,
    limit: int = 20,
    published_after: Optional[str] = None,
    published_before: Optional[str] = None,
) -> str:
    """
    Query the GraphQL security API for CVEs.

    Use this tool when you need a focused list of CVEs filtered by severity or publication date.
    This is the best choice when the user asks about vulnerabilities directly and you only need
    CVE-level fields such as ID, summary, severity, and CVSS score.

    Parameters:
    - severity: Optional severity filter such as LOW, MEDIUM, HIGH, or CRITICAL.
    - limit: Maximum number of CVEs to return.
    - published_after: Optional ISO date/time lower bound.
    - published_before: Optional ISO date/time upper bound.
    """
    gql_query = """
    query GetCVEs($severity: String, $limit: Int, $after: DateTime, $before: DateTime) {
        cves(severity: $severity, limit: $limit, publishedAfter: $after, publishedBefore: $before) {
            id
            summary
            severity
            cvssScore
        }
    }
    """
    variables = {
        "severity": severity,
        "limit": limit,
        "after": published_after,
        "before": published_before,
    }
    result = execute_gql_with_logging(gql_query, variables)

    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data.get("cves", []), default=str)


@mcp.tool()
def get_container_assets(
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    limit: int = 20,
    fields: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """
    Query the GraphQL security API for container assets and nested CVEs.

    Use this tool when you need asset-centric results with related vulnerability data in one call.
    This is the best choice for questions about exposed assets, root-running containers, tags,
    or nested vulnerability details where GraphQL can reduce round trips.

    Parameters:
    - publicly_exposed: Filter to exposed assets only.
    - runs_as_root: Filter to assets running as root.
    - limit: Maximum number of assets to return.
    - fields: List of top-level container fields to return (e.g., ["name", "environment"]).
              If omitted, a default safe set is used.
    - tags: Optional list of tag names to filter by (e.g., ["auth"]).
    """

    container_selection = build_container_selection(fields)

    # If your GraphQL API does NOT support tags as an argument, remove `$tags` and `tags: $tags`
    gql_query = f"""
    query GetContainers(
        $publiclyExposed: Boolean,
        $runsAsRoot: Boolean,
        $limit: Int,
        $tags: [String!]
    ) {{
        containerAssets(
            publiclyExposed: $publiclyExposed,
            runsAsRoot: $runsAsRoot,
            limit: $limit,
            tags: $tags
        ) {{
            {container_selection}
            tags {{
                id
                name
                category
                description
            }}
            cves {{
                id
                summary
                severity
                cvssScore
                publishedAt
                updatedAt
                description
                remediation {{
                    id
                    cveId
                    title
                    priority
                    summary
                    estimatedEffort
                }}
            }}
        }}
    }}
    """

    variables = {
        "publiclyExposed": publicly_exposed,
        "runsAsRoot": runs_as_root,
        "limit": limit,
        "tags": tags,
    }

    result = execute_gql_with_logging(gql_query, variables)

    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"

    data = result.data.get("containerAssets", [])

    # Optional: if you want to enforce projection even if GraphQL returns extra fields,
    # you can post-filter here based on `fields` (commented out by default).
    #
    # if fields:
    #     field_set = {f.split(".")[-1] for f in fields}
    #     projected = []
    #     for asset in data:
    #         projected.append({k: v for k, v in asset.items() if k in field_set})
    #     data = projected

    return json.dumps(data, default=str)


@mcp.tool()
def get_asset_tags(limit: int = 100) -> str:
    """
    Query the GraphQL security API for asset tags.

    Use this tool when you want a tag inventory such as prod, staging, public, internal,
    critical, or business-domain tags. This is useful for filtering and grouping assets
    before asking for nested CVE or remediation details.

    Parameters:
    - limit: Maximum number of tags to return.
    """
    gql_query = """
    query GetAssetTags($limit: Int) {
        assetTags(limit: $limit) {
            id
            name
            category
            description
            createdAt
        }
    }
    """
    variables = {"limit": limit}
    result = execute_gql_with_logging(gql_query, variables)

    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data.get("assetTags", []), default=str)

@mcp.tool()
def get_remediations(priority: Optional[str] = None, limit: int = 100) -> str:
    """
    Query the GraphQL security API for remediation guidance linked to CVEs.

    Use this tool when you need fix guidance, patch recommendations, or remediation summaries
    for vulnerabilities. This is the best choice when the user wants next steps rather than
    just vulnerability identification.

    Parameters:
    - priority: Optional filter such as LOW, MEDIUM, HIGH, or CRITICAL.
    - limit: Maximum number of remediation records to return.
    """
    gql_query = """
    query GetRemediations($priority: String, $limit: Int) {
        remediations(priority: $priority, limit: $limit) {
            id
            cveId
            title
            priority
            summary
            fixSteps
            vendorReferences
            estimatedEffort
            createdAt
            updatedAt
        }
    }
    """
    variables = {
        "priority": priority,
        "limit": limit,
    }
    result = execute_gql_with_logging(gql_query, variables)

    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data.get("remediations", []), default=str)


@mcp.tool()
def get_security_comprehensive(
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    severity: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 20,
) -> str:
    """
    Query the GraphQL security API for a comprehensive nested security dataset.

    Use this tool when you want a broad, joined view of assets, tags, CVEs,
    and remediation in one GraphQL response. This is the best choice for
    comparing GraphQL efficiency against REST because it can satisfy complex
    multi-entity questions in a single request.

    Parameters:
    - publicly_exposed: Filter to exposed assets only.
    - runs_as_root: Filter to assets running as root.
    - severity: Optional CVE severity filter such as LOW, MEDIUM, HIGH, or CRITICAL.
    - priority: Optional remediation priority filter such as LOW, MEDIUM, HIGH, or CRITICAL.
    - limit: Maximum number of container assets to return.
    """
    gql_query = """
    query SecurityComprehensive(
        $publiclyExposed: Boolean,
        $runsAsRoot: Boolean,
        $severity: String,
        $priority: String,
        $limit: Int
    ) {
        containerAssets(
            publiclyExposed: $publiclyExposed,
            runsAsRoot: $runsAsRoot,
            limit: $limit
        ) {
            id
            name
            image
            registry
            environment
            namespace
            serviceName
            publiclyExposed
            runsAsRoot
            createdAt
            updatedAt
            tags {
                id
                name
                category
                description
                createdAt
            }
            cves {
                id
                summary
                severity
                cvssScore
                publishedAt
                updatedAt
                description
                remediation {
                    id
                    cveId
                    title
                    priority
                    summary
                    estimatedEffort
                    createdAt
                    updatedAt
                }
            }
        }
        cves(severity: $severity, limit: $limit) {
            id
            summary
            severity
            cvssScore
            publishedAt
            updatedAt
            remediation {
                id
                cveId
                title
                priority
                summary
                estimatedEffort
            }
        }
        remediations(priority: $priority, limit: $limit) {
            id
            cveId
            title
            priority
            summary
            fixSteps
            vendorReferences
            estimatedEffort
            createdAt
            updatedAt
        }
    }
    """
    variables = {
        "publiclyExposed": publicly_exposed,
        "runsAsRoot": runs_as_root,
        "severity": severity,
        "priority": priority,
        "limit": limit,
    }
    result = execute_gql_with_logging(gql_query, variables)

    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data, default=str)

if __name__ == "__main__":
    try:
        print("Starting graph MCP server...", file=sys.stderr)
        mcp.run(transport="streamable-http", mount_path="/mcp")
    except Exception as e:
        print(f"Graph MCP crashed on startup: {e}", file=sys.stderr)
        raise

@mcp.tool()
def get_security_schema() -> dict:
    """
    Return a compact JSON description of the security graph schema, including
    entities, fields, and relationships.

    Use this tool whenever you need to understand which entities and fields
    exist before forming a query for containers, services, namespaces, images,
    environments, tags, or CVEs.
    """
    return {
        "entities": {
            "ContainerAsset": {
                "fields": {
                    "id": "string",
                    "name": "string",
                    "image": "string",
                    "registry": "string",
                    "environment": "string",
                    "namespace": "string",
                    "serviceName": "string",
                    "publiclyExposed": "boolean",
                    "runsAsRoot": "boolean",
                    "createdAt": "datetime",
                    "updatedAt": "datetime",
                },
                "relations": {
                    "tags": "Tag[]",
                    "cves": "CVE[]",
                },
            },
            "Service": {
                "fields": {
                    "id": "string",
                    "name": "string",
                    "namespace": "string",
                    "environment": "string",
                },
                "relations": {
                    "containers": "ContainerAsset[]",
                },
            },
            "Tag": {
                "fields": {
                    "id": "string",
                    "name": "string",
                    "category": "string",
                    "description": "string",
                }
            },
            "CVE": {
                "fields": {
                    "id": "string",
                    "summary": "string",
                    "severity": "string",
                    "cvssScore": "number",
                    "publishedAt": "datetime",
                    "updatedAt": "datetime",
                    "description": "string",
                },
                "relations": {
                    "remediation": "Remediation[]",
                },
            },
            "Remediation": {
                "fields": {
                    "id": "string",
                    "cveId": "string",
                    "title": "string",
                    "priority": "string",
                    "summary": "string",
                    "estimatedEffort": "string",
                }
            },
            # add more entities as needed
        }
    }        