# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A security-analytics backend exposing the same Postgres-backed data (CVEs, container
assets, tags, remediations) through three layers: a GraphQL API, a REST API, and several
MCP servers so LLM agents (Claude Desktop, etc.) can query it. Python 3.11, FastAPI +
Strawberry (GraphQL) + SQLAlchemy. There is no test suite, linter, or build step.

## Commands

```bash
# Environment
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Postgres (Podman/Docker) — see README for full run command
podman run -d --name my-postgres -p 5432:5432 -e POSTGRES_PASSWORD=vulns docker.io/library/postgres:16

# Create schema + tables (run inside psql / against the DB)
#   CREATE SCHEMA IF NOT EXISTS security;
#   then apply sql/container_table_setup.sql and sql/cve_table_setup.sql

# Seed data — ORDER MATTERS (FK dependencies): CVEs, then assets, then tags+remediations
python seed_data_cve.py
python seed_container_assets.py
python seed_asset_tags_remediation.py

# Run servers (each blocks; run in separate terminals)
python graph.py            # GraphQL  -> http://127.0.0.1:8000/graphql  (+ /health)
python rest.py             # REST     -> http://127.0.0.1:8001/docs (Swagger)

# Run MCP servers (default transport = streamable-http on /mcp)
python mcp_graph_server_v2.py    # canonical GraphQL MCP
python mcp_generic_server.py     # REST-style MCP

# Inspect MCP tools interactively
npx @modelcontextprotocol/inspector@latest
```

There are no automated tests. Verify changes by hitting the GraphQL/REST endpoints or by
running the MCP inspector.

## Architecture

### Shared data core
`models.py` (SQLAlchemy ORM) and `schema.py` (Strawberry GraphQL + resolvers) are the
foundation everything else imports. The entities live in the Postgres `security` schema:

- **CVE** — primary key is `cve_id` (TEXT, e.g. `CVE-2025-10001`), not an int. `references`
  is *not* a column; it is derived in the resolver from the `raw_data` JSONB column.
- **ContainerAsset** — serial int id; many-to-many to CVEs (`container_asset_cves`) and to
  AssetTags (`container_asset_tags`). The `cves` relationship is `lazy="joined"`.
- **AssetTag**, **Remediation** (1:1 with CVE via unique `cve_id` FK).

`schema.py` is the source of truth for GraphQL field/argument names. Note the camelCase
exposed to clients (`publiclyExposed`, `cvssScore`, `publishedAfter`) and that the `cves`
query filters by `severities` (a list), not `severity`.

### Two API surfaces over the same data
- **GraphQL**: `graph.py` mounts `schema.py` via `GraphQLRouter` (port 8000).
- **REST**: `rest.py` re-implements the same queries as plain FastAPI routes returning
  hand-built dicts (port 8001). It does *not* call GraphQL — it goes straight to the DB.

### MCP layer (the point of the repo)
Several MCP server variants exist; they differ in how they reach the data:

| File | Tools | How it queries |
|------|-------|----------------|
| `mcp_graph_server_v2.py` | `get_security_schema`, `query_security_graph`, `ping` | In-process `schema.execute_sync(...)` — builds GraphQL strings, no HTTP |
| `mcp_graph_server_v1.py` | older container-focused tools | In-process GraphQL (superseded by v2) |
| `mcp_generic_server.py` | `list_container_assets`, `list_cves`, `list_asset_tags`, `list_remediations` | Direct SQLAlchemy against the DB |
| `raw_mcp_graphql.py` | `cves`, `cve`, `containerAssets`, … | Hand-rolled JSON-RPC over stdin/stdout calling the GraphQL HTTP endpoint (port 8000) |

The most non-obvious code is `query_security_graph` in `mcp_graph_server_v2.py`: it takes
a generic `(entity, filters, fields, limit)` request and dynamically assembles a GraphQL
query — `build_selection_for_entity` turns dot-paths (`cves.remediation.title`) into nested
selection sets, `validate_field_paths` prunes them against the hardcoded schema map in
`get_security_schema`, and `build_filters_arguments` maps filter keys to GraphQL args
(e.g. `severity`→`severities`, `tags.name`→`tags`, `{in: [...]}` operators) and infers
variable types. When you change the GraphQL schema, this hardcoded map and the mapping
tables (`ENTITY_TO_ROOT_FIELD`, `IN_FILTER_ARG_MAP`) must be updated to match, or
`query_security_graph` will silently drop fields/filters.

## Gotchas

- **`DATABASE_URL` is hardcoded** (`postgresql+psycopg2://postgres:vulns@localhost:5432/postgres`)
  in `schema.py`, `rest.py`, and `mcp_generic_server.py`. Change it in all three.
- **MCP transport switching**: servers default to `mcp.run(transport="streamable-http", ...)`.
  For Claude Desktop / stdio integration, switch to the commented `mcp.run(transport="stdio")`
  line. Claude Desktop logs land in `~/Library/Logs/Claude/mcp-server-*.log` (macOS).
- **`get_security_schema` filter hints are advisory**: the operator / `allowedValues` hints
  it returns guide the LLM but are not all enforced by the resolvers in `schema.py` (e.g.
  `serviceName` only supports exact match). Trust `schema.py` for what actually resolves.
