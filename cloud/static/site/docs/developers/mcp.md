# MCP tools for your site

Many agents discover and call tools through the Model Context Protocol (MCP). Auth Your Agent can generate an MCP server from your site's OpenAPI description. Each tool call carries the agent's pass and a DPoP proof, and tools you mark as sensitive ask the person's phone first.

Two tools in the repository's `mcp_layer/` folder do this:

1. `openapi_to_manifest.py` reads your OpenAPI 3 description and writes a **manifest**: the list of tools, their parameters, scopes and which need step-up. You review and edit it.
2. `forge.py` turns the manifest and an agent key into a standalone MCP server file.

## Mark your operations

Add an `x-authyouragent` extension to each operation agents may use:

```yaml
paths:
  /jobs/{job_id}/apply:
    post:
      x-authyouragent:
        name: apply_to_job
        scopes: [list, apply]
        stepup: true
        description: Apply to a job. Needs a one-time phone approval.
```

In FastAPI, the same goes in `openapi_extra={"x-authyouragent": {...}}` on the route; see `demo/app.py`.

| Field | Meaning |
|---|---|
| `name` | Tool name agents see. |
| `scopes` | Scopes the agent must hold to call it. |
| `stepup` | `true` if every call needs a fresh phone approval. |
| `description` | Shown to the agent's model. Say what it does and what it costs. |

Operations without the extension are also picked up, unless you pass `--only-with-x-authyouragent`. Their scope is then guessed from the method (`GET` → `read`, `POST`/`PUT` → `write`, `DELETE` → `delete`), and health, docs, admin and auth routes are skipped. Explicit extensions are safer.

## Generate the manifest

```
python mcp_layer/openapi_to_manifest.py \
    --spec https://jobs.example.com/openapi.json \
    --name "Job Board" --site jobs.example.com \
    --base-url https://jobs.example.com \
    --only-with-x-authyouragent \
    --out manifests/jobs.json
```

`--spec` accepts a URL or a file, JSON or YAML (YAML needs PyYAML). Read the result before going further; it decides what agents can do.

## Build the server

The server acts as one agent, so it needs that agent's key: a JSON file with `agent_id`, `privkey` (or `private_key_pem`) and `jwk`. If you used `keygen`, add the `agent_id` the app gave you to its `agent_key` object and save that object as the file.

```
python mcp_layer/forge.py \
    --manifest manifests/jobs.json \
    --agent-key agent-key.json \
    --external-key \
    --out jobs_mcp.py
```

With `--external-key`, the private key is not written into the generated file; the server reads it from the file named in `AUTHYOURAGENT_AGENT_KEY_FILE` when it starts. Without it, the key is embedded and the generated file (written readable by its owner only) must be kept as private as the key.

The generated file needs `httpx`, `cryptography`, `pyjwt` and `mcp`.

## Run it

Locally, over standard input and output, which is what most desktop MCP clients use:

```
AUTHYOURAGENT_AGENT_KEY_FILE=agent-key.json python jobs_mcp.py
```

Over the network (streamable HTTP at `/mcp`, or `--transport sse` for `/sse`):

```
AUTHYOURAGENT_AGENT_KEY_FILE=agent-key.json \
AUTHYOURAGENT_MCP_TOKEN=<at least 32 random characters> \
python jobs_mcp.py --transport http --host 0.0.0.0 --port 8765 \
    --allowed-host mcp.example.com
```

Network mode refuses to start without `AUTHYOURAGENT_MCP_TOKEN`. Clients must send it as `Authorization: Bearer <token>`. `--allowed-host` lists the host names the server answers to when it listens beyond this machine.

## What happens on a call

1. The first call asks the person's phone for access to your site with the scopes in the manifest, and waits for approval.
2. Each call signs a fresh DPoP proof and sends the pass.
3. A step-up tool that gets `403 stepup_required` asks the phone again, then retries once.

## Sites without an OpenAPI description

`mcp_layer/record_cdp.py` records the requests a browser makes while someone uses the site (through Chrome's DevTools protocol, or from a saved HAR file) and writes a draft manifest from them. The draft always needs review: it can only guess which requests are safe to expose.
