import sys
import json
from functools import lru_cache
from typing import Any, Dict, List, Optional,Tuple

from mcp.server.fastmcp import FastMCP

from schema import schema


mcp = FastMCP("Security API GraphQL", host="127.0.0.1", port=8000)


def execute_gql_with_logging(gql_query: str, variables: dict):
    # schema already has ClaudeQueryLogger attached in schema.py.
    # NOTE: must log to stderr — any stdout write corrupts the JSON-RPC stream
    # when running under transport="stdio".
    print("gql_query ", gql_query, file=sys.stderr)
    return schema.execute_sync(gql_query, variable_values=variables)


# ===== Tool 1: schema introspection =====


@mcp.tool()
def get_security_schema() -> dict:
    """
    Return a compact JSON description of the security graph schema, including
    entities, fields, relationships, and filter capabilities.
    """
    print("call get_security_schema", file=sys.stderr)
    return _security_schema()


@lru_cache(maxsize=1)
def _security_schema() -> dict:
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
                        "operators": ["eq"],
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
                        "operators": ["before", "after"],
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
                # The root assetTags query takes no filters. To filter by tag,
                # query ContainerAsset with the "tags.name" relation filter.
                "filters": {},
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
                    "remediation": "Remediation",
                },
                "filters": {
                    "severity": {
                        "type": "string",
                        "operators": ["eq", "in"],
                        "allowedValues": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    },
                    "publishedAt": {
                        "type": "datetime",
                        "operators": ["before", "after"],
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
                        "operators": ["eq"],
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

def get_entity_relations():
    schema_data = _security_schema()
    entities = schema_data["entities"]

    relation_map = {}

    for entity_name, entity_info in entities.items():
        relation_map[entity_name] = entity_info.get("relations", {})

    return relation_map


def validate_field_paths(entity: str, fields: List[str]) -> List[str]:
    """
    Remove invalid recursive/nonsensical field paths.
    """

    schema_data = _security_schema()
    entities = schema_data["entities"]

    valid_fields = []

    for field_path in fields:
        parts = field_path.split(".")

        current_entity = entity
        valid = True

        for i, part in enumerate(parts):

            entity_info = entities.get(current_entity)
            if not entity_info:
                valid = False
                break

            is_last = i == len(parts) - 1

            # scalar field
            if part in entity_info.get("fields", {}):
                if not is_last:
                    valid = False
                break

            # relation field
            elif part in entity_info.get("relations", {}):
                relation_type = entity_info["relations"][part]

                # convert "CVE[]" -> "CVE"
                current_entity = relation_type.replace("[]", "")

                if is_last:
                    valid = False

            else:
                valid = False
                break

        if valid:
            valid_fields.append(field_path)
        else:
            print(
                f"Skipping invalid field path: {field_path}",
                file=sys.stderr,
            )

    return valid_fields


def build_filters_arguments(
    filters: Dict[str, Any],
) -> (str, Dict[str, Any], Dict[str, str]):
    """
    Build:
      - GraphQL argument string
      - variables map
      - variable type map
    """

    arg_lines = []
    variables: Dict[str, Any] = {}
    variable_types: Dict[str, str] = {}

    # Relation filters that map onto a root-query argument.
    SUPPORTED_RELATION_FILTERS = {
        "tags.name": "tags",
    }
    # Singular filter keys whose GraphQL argument is a list. The value is always
    # coerced to a list, whether it arrived as a scalar, { "in": [...] }, or a
    # bare list like ["CRITICAL"].
    LIST_ARG_MAP = {
        "severity": "severities",
        "tag": "tags",
        "tags.name": "tags",
    }
    # Datetime range filters expressed as operator objects, e.g.
    # { "publishedAt": { "after": "2025-01-01" } }. These map onto the resolver's
    # separate <base>After / <base>Before arguments.
    DATE_RANGE_BASE = {
        "publishedAt": "published",
        "createdAt": "created",
    }

    def infer_type(value: Any) -> str:
        if isinstance(value, list):
            if value and all(isinstance(v, bool) for v in value):
                elem = "Boolean"
            elif value and all(isinstance(v, bool) is False and isinstance(v, int) for v in value):
                elem = "Int"
            elif value and all(isinstance(v, (int, float)) for v in value):
                elem = "Float"
            else:
                elem = "String"
            return f"[{elem}!]"
        # bool must be checked before int (bool is a subclass of int)
        if isinstance(value, bool):
            return "Boolean"
        if isinstance(value, int):
            return "Int"
        if isinstance(value, float):
            return "Float"
        return "String"

    def add_var(gql_arg_name: str, value: Any, gql_type: str) -> None:
        arg_lines.append(f"{gql_arg_name}: ${gql_arg_name}")
        variables[gql_arg_name] = value
        variable_types[gql_arg_name] = gql_type

    for key, value in filters.items():

        # Skip unsupported nested relation filters (only tags.name is wired up).
        if "." in key and key not in SUPPORTED_RELATION_FILTERS:
            print(f"Skipping unsupported nested filter: {key}", file=sys.stderr)
            continue

        #
        # Datetime range filters -> separate <base>After / <base>Before args.
        #
        if key in DATE_RANGE_BASE:
            base = DATE_RANGE_BASE[key]
            if not isinstance(value, dict):
                print(
                    f"Skipping {key}: expected an operator object like "
                    f'{{"after": ...}} / {{"before": ...}}',
                    file=sys.stderr,
                )
                continue
            if "after" in value:
                add_var(f"{base}After", value["after"], "DateTime")
            if "before" in value:
                add_var(f"{base}Before", value["before"], "DateTime")
            for op in value:
                if op not in ("after", "before"):
                    print(
                        f"Skipping unsupported operator '{op}' on {key} "
                        f"(only after/before resolve)",
                        file=sys.stderr,
                    )
            continue

        #
        # Normalize operator objects. Only "in" and "eq" map onto resolver
        # arguments; range/text operators (gt, lt, contains, between, ...) have
        # no resolver support, so skip rather than emit a query that errors.
        #
        if isinstance(value, dict):
            if "in" in value:
                value = value["in"]
            elif "eq" in value:
                value = value["eq"]
            else:
                print(
                    f"Skipping unsupported operator object on '{key}': {value}",
                    file=sys.stderr,
                )
                continue

        gql_arg_name = key

        #
        # Coerce list-valued arguments. The value is forced to a list so a scalar
        # like { "severity": "CRITICAL" } still maps to severities: ["CRITICAL"].
        #
        if gql_arg_name in LIST_ARG_MAP:
            gql_arg_name = LIST_ARG_MAP[gql_arg_name]
            if not isinstance(value, list):
                value = [value]

        add_var(gql_arg_name, value, infer_type(value))

    arg_str = ", ".join(arg_lines)

    return arg_str, variables, variable_types


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
        { "severity": ["CRITICAL"] }
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
        fields = validate_field_paths(entity, fields or [])
        selection = build_selection_for_entity(entity, fields)
        print("selection", selection, file=sys.stderr)

        # Build filter arguments + variables + GraphQL variable types
        filters_arg_str, filter_vars, variable_types = build_filters_arguments(filters)

        print("filters_arg_str", filters_arg_str, file=sys.stderr)
        print("filter_vars", filter_vars, file=sys.stderr)
        print("variable_types", variable_types, file=sys.stderr)

        # Limit argument
        filters_with_limit = (
            f"{filters_arg_str}, limit: $limit"
            if filters_arg_str
            else "limit: $limit"
        )

        # Build GraphQL variable definitions
        variable_defs = []

        for var_name, gql_type in variable_types.items():
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