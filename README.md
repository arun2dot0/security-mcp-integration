# CVE & Container Security API (Postgres + FastAPI + GraphQL + MCP)

This project provides a minimal security analytics backend with:

- A PostgreSQL schema for CVEs and container assets.
- Seed scripts for realistic sample data.
- Both GraphQL and REST APIs (FastAPI + Strawberry + SQLAlchemy).
- MCP servers for GraphQL and REST, so tools/agents (e.g. Claude, Next.js demo) can query it.

---

## 1. Requirements

- Python 3.11+
- PostgreSQL (tested with 14+)
- Podman or Docker
- `pip` / `venv`

---

## 2. PostgreSQL via Podman

Create a volume and run Postgres:

```bash
podman volume create pg-data

podman run -d --name my-postgres -p 5432:5432 \
  -e POSTGRES_PASSWORD=vulns \
  -v /pg-data:/var/lib/postgresql/data:Z \
  docker.io/library/postgres:16

podman exec -it my-postgres psql -U postgres
```

Inside `psql`, create the `security` schema:

```sql
CREATE SCHEMA IF NOT EXISTS security;
```

Run the SQL files in the `sql` folder to create tables.

---

## 3. Python Environment & Dependencies

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate    # On Windows: .venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 4. Database Configuration & Seed Data

Run the sql scripts in sql folder 

Set the database URL in `schema.py` (adjust if needed):

```python
DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
```

Seed the CVE and container data:

```bash
python seed_data_cve.py
python seed_container_assets.py
python seed_asset_tags_remediation.py
```

Verify in `psql`:

```sql
SELECT * FROM security.cves LIMIT 5;
```

---

## 5. GraphQL API

Start the GraphQL server:

```bash
python graph.py
```

Endpoints:

- GraphQL: `http://127.0.0.1:8000/graphql`
- Health: `http://127.0.0.1:8000/health`

### Example GraphQL Queries

List CVEs:

```graphql
query {
  cves(limit: 10) {
    id
    summary
    severity
    cvssScore
    publishedAt
    references
  }
}
```

Get a single CVE:

```graphql
query {
  cve(id: "CVE-2025-10001") {
    id
    summary
    severity
    cvssScore
    references
  }
}
```

List container assets with CVEs:

```graphql
query {
  containerAssets(publiclyExposed: true, runsAsRoot: true) {
    id
    name
    image
    publiclyExposed
    runsAsRoot
    cves {
      id
      summary
      severity
    }
  }
}
```

Get one container asset:

```graphql
query {
  containerAsset(id: 1) {
    name
    image
    publiclyExposed
    runsAsRoot
    cves {
      id
      cvssScore
    }
  }
}
```

> Note: `references` is derived from the `raw_data` JSON column on `security.cves`.

---

## 6. REST API

Start the REST server:

```bash
python rest.py
```

Endpoint:

- Swagger UI: `http://127.0.0.1:8001/docs`

The REST API exposes similar functionality for listing CVEs and container assets via HTTP endpoints.

---

## 7. Project Structure (Core Backend)

```text
.
├── graph.py                 # GraphQL server (FastAPI + Strawberry)
├── rest.py                  # REST API server (FastAPI)
├── mcp_graph_server.py      # MCP server wrapping the GraphQL API
├── mcp_rest_server.py       # MCP server wrapping the REST API
├── models.py                # SQLAlchemy models (CVE, container assets, etc.)
├── schema.py                # GraphQL schema & resolvers
├── seed_data_cve.py         # Seed script: CVEs
├── seed_container_assets.py # Seed script: container assets
├── seed_asset_tags_remediation.py # Seed script: tags & remediation
├── sql/                     # DDL for security schema & tables
├── requirements.txt
└── README.md
```

---

## 8. GraphQL MCP Setup

Install GraphQL MCP tooling:

```bash
brew install graphql-cli

pip3 install graphql-mcp
pip3 install mcp-graphql

pip3 show graphql-mcp
pip3 show mcp-graphql
```

Run the generic GraphQL MCP server:

```bash
export GRAPHQL_API_ENDPOINT="http://127.0.0.1:8000/graphql"
# Optional:
# export GRAPHQL_API_KEY="..."
# export WHITELISTED_QUERIES='["cves","cve","containerAssets","containerAsset"]'

graphql-mcp-server
```

---

## 9. fastmcp

Install `fastmcp` for the Python MCP servers:

```bash
pip install fastmcp httpx
```

This is used by `mcp_graph_server.py` and `mcp_rest_server.py` to expose dedicated MCP tools over stdio or HTTP.

---

## 10. Claude MCP Configuration

Run the mcp_rest_server.py , mcp_graph_server_v2.py 
```
  run in stdio for claude integration
  mcp.run(transport="stdio")
```


Example Claude MCP config for Graph:

```json
"mcpServers": {
    "graph-mcp": {
      "command": "python",
      "args": ["/projectfolder/mcp_graph_server_v2.py"]
    }
  }
```

For REST:

```json
"mcpServers": {
    "graph-mcp": {
      "command": "python",
      "args": ["/projectfolder/mcp_rest_server.py"]
    }
  }
```


Prompt claude to not use cache
```
Every time I ask about security data (containers, CVEs, tags, etc.), you MUST:
1. Call the MCP tool `query_security_graph` (or the relevant tool)
2. Do NOT reuse any previous tool result from earlier in this chat
3. Treat each request as if no prior data exists
4. This query requires multiple steps. For each distinct entity or filter, call query_security_graph separately.


If you are unsure whether to call the tool, always call it.
```

Monitor MCP server logs (macOS default):

```bash
tail -f ~/Library/Logs/Claude/mcp-server-graph-mcp.log
# or
tail -f ~/Library/Logs/Claude/mcp-server-rest-mcp.log
```

---

## 11. Dedicated MCP Servers (Graph & REST)

Instead of the generic GraphQL MCP, you can run first-class MCP servers that expose domain-specific tools:

Graph integration:

```bash
python mcp_graph_server.py
```

REST integration:

```bash
python mcp_generic_server.py
```

These wrap the GraphQL and REST APIs respectively and provide tools like `getcontainerassets`, `getcves`, `listcontainerassets`, and `listcves`.

---

## 12. Example Promptions

- Complex 
Good “agent” questions to drive multi-step or aggregated behavior:

- “Show the top 5 publicly exposed assets that have at least one critical CVE, and include only the asset name, namespace, CVE id, severity, and score.”  
- “Find assets that are public or run as root and list only the CVEs that have CVSS score greater than 8.”
- "List all public container assets in prod with CVEs and severity."
- "Show containers running as root and are public"
- "Give me recent CRITICAL CVEs affecting my containers."
- "Generate a prioritized remediation plan for production assets, grouped by severity and estimated effort.show affected assets"
- "find name and environment for container assets with tag auth"

- get me cve and remediation details for CVE-2025-10007

---

## 13. MCP Inspector

You can introspect and test MCP servers with the inspector:

```bash
npx @modelcontextprotocol/inspector@latest
```

Point it at your MCP servers (Graph or REST) to explore available tools and responses interactively.