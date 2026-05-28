import sys
import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from strawberry.extensions import SchemaExtension

from schema import schema


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
    # schema already has ClaudeQueryLogger attached in schema.py
    print("gql_query ",gql_query)
    return schema.execute_sync(gql_query, variable_values=variables)


# ===== Tool 1: schema introspection =====


@mcp.tool()
def get_security_schema() -> dict:
    """
    Return a compact JSON description of the security graph schema, including
    entities, fields, relationships, and filter capabilities.
    """
    print("call get_security_schema", file=sys.stderr)
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
                "filters": {
                    # exact match
                    "environment": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["dev", "staging", "prod"],
                    },
                    "namespace": {
                        "type": "string",
                        "operators": ["eq", "in"],
                    },
                    "serviceName": {
                        "type": "string",
                        "operators": ["eq", "contains"],
                    },
                    "publiclyExposed": {
                        "type": "boolean",
                        "operators": ["eq"],
                    },
                    "runsAsRoot": {
                        "type": "boolean",
                        "operators": ["eq"],
                    },
                    "createdAt": {
                        "type": "datetime",
                        "operators": ["before", "after", "between"],
                    },
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
                "filters": {
                    "environment": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["dev", "staging", "prod"],
                    },
                    "name": {
                        "type": "string",
                        "operators": ["eq", "contains"],
                    },
                },
            },
            "Tag": {
                "fields": {
                    "id": "string",
                    "name": "string",
                    "category": "string",
                    "description": "string",
                },
                "filters": {
                    "name": {
                        "type": "string",
                        "operators": ["eq", "in"],
                    },
                    "category": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["compliance", "auth", "network"],
                    },
                },
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
                "filters": {
                    "severity": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    },
                    "cvssScore": {
                        "type": "number",
                        "operators": ["gt", "gte", "lt", "lte", "between"],
                    },
                    "publishedAt": {
                        "type": "datetime",
                        "operators": ["before", "after", "between"],
                    },
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
                },
                "filters": {
                    "priority": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["LOW", "MEDIUM", "HIGH"],
                    },
                },
            },
        }
    }


# ===== Tool 2: generic graph query =====

# You can refine this mapping based on your GraphQL schema
ENTITY_TO_ROOT_FIELD = {
    "ContainerAsset": "containerAssets",
    "Service": "services",
    "Tag": "assetTags",
    "CVE": "cves",
    "Remediation": "remediations",
}


def build_selection_for_entity(
    entity: str,
    fields: Optional[List[str]],
) -> str:
    """
    Build nested GraphQL selection sets from dot-path fields.

    Supports:
      - name
      - cves.summary
      - cves.remediation.title
      - tags.name
    """

    if not fields:
        return "    id\n    name"

    tree = {}

    # Build nested tree structure
    for field in fields:
        parts = field.split(".")
        current = tree

        for part in parts:
            current = current.setdefault(part, {})

    def render(node: Dict[str, Any], indent: int = 1) -> List[str]:
        lines = []
        prefix = "    " * indent

        for key, child in node.items():
            if child:
                lines.append(f"{prefix}{key} {{")
                lines.extend(render(child, indent + 1))
                lines.append(f"{prefix}}}")
            else:
                lines.append(f"{prefix}{key}")

        return lines

    return "\n".join(render(tree))


def build_filters_arguments(filters: Dict[str, Any]) -> (str, Dict[str, Any]):
    """
    Given a filters dict like:
      { "environment": "prod", "tags.name": "auth", "severity": "CRITICAL" }
    build:
      - GraphQL argument string
      - variables map

    For now this is deliberately simple and maps all filters to variables.
    You can refine per-entity later.
    """
    arg_lines = []
    variables: Dict[str, Any] = {}

    for key, value in filters.items():
        SUPPORTED_RELATION_FILTERS = {
            "tags.name": "tags",
        }

        if "." in key and key not in SUPPORTED_RELATION_FILTERS:
            print(
                f"Skipping unsupported nested filter: {key}",
                file=sys.stderr,
            )
            continue

        # Special handling for relation filters
        gql_arg_name = key

        if key == "tags.name":
            gql_arg_name = "tags"

            # resolver expects List[str]
            if not isinstance(value, list):
                value = [value]

        var_name = gql_arg_name.replace(".", "_")

        arg_lines.append(f"{gql_arg_name}: ${var_name}")
        variables[var_name] = value

    arg_str = ", ".join(arg_lines)
    return arg_str, variables

from typing import Any, Dict, List, Optional, Union
import sys
import json




@mcp.tool()
def query_security_graph(
    entity: str,
    filters: Optional[Dict[str, Any]] = None,
    fields: Optional[List[str]] = None,
    limit: int = 50,
) -> str:
    """
    Generic query tool for the security graph.

    Parameters:
    - entity: Root entity name from the schema (e.g. "ContainerAsset", "CVE", "Tag").
    - filters: Field-based filters for the root entity or simple relations.
      Examples:
        { "environment": "prod", "publiclyExposed": true }
        { "tags.name": "auth" }
        { "severity": "CRITICAL" }
    - fields: Fields to return. Supports nested paths:
        "name", "environment"
        "tags.name", "tags.category"
        "cves.summary", "cves.severity", "cves.remediation.title"
      If omitted, a default set is used.
    - limit: Max number of items to return.
    """
    try:
        print("called query_security_graph", file=sys.stderr)

        root_field = ENTITY_TO_ROOT_FIELD.get(entity)
        if not root_field:
            msg = f"Unknown entity '{entity}'. See get_security_schema for valid entities."
            print(msg, file=sys.stderr)
            return json.dumps({"error": msg})

        filters = filters or {}
        print("filters", filters, file=sys.stderr)

        # Build selection set
        selection = build_selection_for_entity(entity, fields)
        print("selection", selection, file=sys.stderr)

        # Build filter arguments and variable definitions
        filters_arg_str, filter_vars = build_filters_arguments(filters)
        print("filters_arg_str", filters_arg_str, file=sys.stderr)
        print("filter_vars", filter_vars, file=sys.stderr)

        # Limit argument
        filters_with_limit = (
            f"{filters_arg_str}, limit: $limit" if filters_arg_str else "limit: $limit"
        )

        # Build variable definitions for GraphQL
        # For simplicity, treat all filter variables as String; you can refine types later.
        # filter_var_defs = " ".join(
        #     [f"${name}: String" for name in filter_vars.keys()]
        # )
        # if filter_var_defs:
        #     filter_var_defs = " " + filter_var_defs

        #openai
        # Build variable definitions using schema filter types

        TYPE_MAP = {
            "string": "String",
            "boolean": "Boolean",
            "number": "Float",
            "datetime": "DateTime",
        }

        schema_data = get_security_schema()
        entity_schema = schema_data["entities"][entity]

        variable_defs = []

        for field_name in filters.keys():

            # Special relation filter handling
            if field_name == "tags.name":
                variable_defs.append("$tags: [String!]")
                continue

            filter_meta = entity_schema["filters"].get(field_name)

            if not filter_meta:
                continue

            schema_type = filter_meta.get("type", "string")

            gql_type = TYPE_MAP.get(schema_type, "String")

            var_name = field_name.replace(".", "_")

            variable_defs.append(f"${var_name}: {gql_type}")

        filter_var_defs = ", ".join(variable_defs)

        if filter_var_defs:
            filter_var_defs = ", " + filter_var_defs

        gql_query = f"""
        query QuerySecurityGraph($limit: Int{filter_var_defs}) {{
            {root_field}({filters_with_limit}) {{
            {selection}
            }}
        }}
        """
        print("gql_query", gql_query, file=sys.stderr)

        variables = {"limit": limit}
        variables.update(filter_vars)

        result = execute_gql_with_logging(gql_query, variables)

        # Defensive checks on result
        if hasattr(result, "errors") and result.errors:
            err_list = [str(e) for e in result.errors]
            print("GraphQL Errors:", err_list, file=sys.stderr)
            return json.dumps({"error": "GraphQL Errors", "details": err_list})

        data = getattr(result, "data", None) or {}
        collection = data.get(root_field, [])
        return json.dumps(collection, default=str)

    except Exception as e:
        # Catch any unexpected exceptions, log them, return structured error
        print("query_security_graph: unexpected exception", file=sys.stderr)
        print(type(e).__name__, str(e), file=sys.stderr)
        return json.dumps(
            {
                "error": "Internal error in query_security_graph",
                "exception": type(e).__name__,
                "message": str(e),
            }
        )

@mcp.tool()
def ping(message: str) -> str:
    print("PING TOOL CALLED:", message, file=sys.stderr)
    return f"pong: {message}"

if __name__ == "__main__":
    try:
        print("Starting graph MCP server...", file=sys.stderr)
        mcp.run(transport="streamable-http", mount_path="/mcp")
        # mcp.run(transport="stdio")
    except Exception as e:
        print(f"Graph MCP crashed on startup: {e}", file=sys.stderr)
        raise