#!/usr/bin/env python3
import json
import sys
from typing import Any, Dict, Optional
import http.client
from urllib.parse import urlparse

GRAPHQL_ENDPOINT = "http://127.0.0.1:8000/graphql"

def call_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = urlparse(GRAPHQL_ENDPOINT)
    conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=30)
    body = json.dumps({"query": query, "variables": variables or {}})
    headers = {"Content-Type": "application/json"}
    conn.request("POST", url.path or "/graphql", body, headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError(f"GraphQL error {resp.status}: {data!r}")
    payload = json.loads(data.decode("utf-8"))
    if "errors" in payload:
        raise RuntimeError(f"GraphQL errors: {payload['errors']}")
    return payload.get("data", {})

def send_response(id: Any, result: Any = None, error: Any = None):
    response = {"jsonrpc": "2.0", "id": id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def tool_result(text: str):
    return {
        "content": [
            {
                "type": "text",
                "text": text,
            }
        ]
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "cve-graphql-mcp",
                    "version": "0.2.0",
                },
                "capabilities": {
                    "tools": {}
                },
            }
            send_response(req_id, result=result)

        elif method == "tools/list":
            tools = [
                {
                    "name": "cves",
                    "description": "List CVEs with optional severity and publication date filters.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string"},
                            "limit": {"type": "integer", "default": 20},
                            "published_after": {"type": "string"},
                            "published_before": {"type": "string"},
                        },
                    },
                },
                {
                    "name": "cve",
                    "description": "Get a single CVE by id.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                        },
                        "required": ["id"],
                    },
                },
                {
                    "name": "containerAssets",
                    "description": "List container assets with optional filters.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "publicly_exposed": {"type": "boolean"},
                            "runs_as_root": {"type": "boolean"},
                            "limit": {"type": "integer", "default": 20},
                        },
                    },
                },
                {
                    "name": "containerAsset",
                    "description": "Get one container asset by id.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                        },
                        "required": ["id"],
                    },
                },
                {
                    "name": "assetTags",
                    "description": "List asset tags such as prod, staging, public, internal, critical, or business tags.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "default": 100},
                        },
                    },
                },
                {
                    "name": "remediations",
                    "description": "List remediation guidance for CVEs, optionally filtered by priority.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "priority": {"type": "string"},
                            "limit": {"type": "integer", "default": 100},
                        },
                    },
                },
            ]
            send_response(req_id, result={"tools": tools})

        elif method == "tools/call":
            params = req.get("params") or {}
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            try:
                if tool_name == "cves":
                    q = """
                    query Cves($severity: String, $limit: Int!, $createdAfter: DateTime, $createdBefore: DateTime) {
                      cves(severity: $severity, limit: $limit, publishedAfter: $createdAfter, publishedBefore: $createdBefore) {
                        id
                        summary
                        severity
                        cvssScore
                        publishedAt
                        updatedAt
                      }
                    }
                    """
                    vars = {
                        "severity": arguments.get("severity"),
                        "limit": arguments.get("limit", 20),
                        "createdAfter": arguments.get("published_after"),
                        "createdBefore": arguments.get("published_before"),
                    }
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                elif tool_name == "cve":
                    q = """
                    query Cve($id: String!) {
                      cve(id: $id) {
                        id
                        summary
                        severity
                        cvssScore
                        publishedAt
                        updatedAt
                        references
                        remediation {
                          id
                          cveId
                          title
                          priority
                          summary
                          fixSteps
                          vendorReferences
                          estimatedEffort
                        }
                      }
                    }
                    """
                    vars = {"id": arguments["id"]}
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                elif tool_name == "containerAssets":
                    q = """
                    query ContainerAssets($publiclyExposed: Boolean, $runsAsRoot: Boolean, $limit: Int!) {
                      containerAssets(publiclyExposed: $publiclyExposed, runsAsRoot: $runsAsRoot, limit: $limit) {
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
                        }
                        cves {
                          id
                          severity
                          cvssScore
                          remediation {
                            id
                            cveId
                            title
                            priority
                            summary
                          }
                        }
                      }
                    }
                    """
                    vars = {
                        "publiclyExposed": arguments.get("publicly_exposed"),
                        "runsAsRoot": arguments.get("runs_as_root"),
                        "limit": arguments.get("limit", 20),
                    }
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                elif tool_name == "containerAsset":
                    q = """
                    query ContainerAsset($id: Int!) {
                      containerAsset(id: $id) {
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
                        }
                        cves {
                          id
                          severity
                          cvssScore
                          remediation {
                            id
                            cveId
                            title
                            priority
                            summary
                          }
                        }
                      }
                    }
                    """
                    vars = {"id": arguments["id"]}
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                elif tool_name == "assetTags":
                    q = """
                    query AssetTags($limit: Int!) {
                      assetTags(limit: $limit) {
                        id
                        name
                        category
                        description
                        createdAt
                      }
                    }
                    """
                    vars = {"limit": arguments.get("limit", 100)}
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                elif tool_name == "remediations":
                    q = """
                    query Remediations($priority: String, $limit: Int!) {
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
                    vars = {
                        "priority": arguments.get("priority"),
                        "limit": arguments.get("limit", 100),
                    }
                    data = call_graphql(q, vars)
                    send_response(req_id, result=tool_result(json.dumps(data, default=str)))

                else:
                    send_response(
                        req_id,
                        error={"code": -32601, "message": f"Unknown tool {tool_name}"},
                    )
            except Exception as e:
                send_response(
                    req_id,
                    error={
                        "code": -32000,
                        "message": f"Tool execution error: {e}",
                    },
                )

        else:
            send_response(
                req_id,
                error={"code": -32601, "message": f"Unknown method {method}"},
            )

if __name__ == "__main__":
    main()