<!-- mcp-name: com.authyouragent.mcp -->
# authyouragent (Python)

SDK for [Auth Your Agent](https://authyouragent.com): let AI agents act for a person on websites, with the person's approval on their phone.

- `AgentClient`: an agent asks for access, then calls sites with a short-lived pass and a fresh DPoP proof (RFC 9449) on every request.
- `SiteVerifier`: a website checks each call in one line.
- **Take over**: when an agent hits a login wall, CAPTCHA, or 2FA, the owner drives the agent's browser live from their phone. Four MCP tools: `check_login_wall`, `request_takeover`, `wait_for_takeover`, `report_site`.

Python 3.9+. Depends on `httpx`, `pyjwt`, `cryptography`.

Full documentation: https://authyouragent.com/docs/developers/quickstart

## Install

```
pip install "authyouragent[mcp]"
```

This installs the SDK plus the MCP server (with Take over support).

For just the SDK without MCP:

```
pip install authyouragent
```

For Take over support (Playwright + websockets):

```
pip install "authyouragent[takeover]"
```

## MCP server

The `authyouragent-mcp` command starts an MCP server with four tools:

1. **`check_login_wall`** -- examines the current page and reports whether it is blocked (password, CAPTCHA, 2FA, or sign-in approval).
2. **`request_takeover`** -- sends a push notification to the user's phone. Blocks until they finish or 4 minutes expire. Returns `done`, `cancelled`, `expired`, or `agent_left`.
3. **`wait_for_takeover`** -- if `request_takeover` timed out, call this to keep waiting.
4. **`report_site`** -- report a site where takeover did not work, so coverage can be improved.

### Configuration

Set these environment variables:

```
AYA_CLOUD=https://authyouragent.com
AYA_AGENT_ID=ag_xxxxx
AYA_KEY_FILE=/path/to/agent-key.pem
```

### Hermes

```yaml
mcp:
  authyouragent:
    enabled: true
    command: authyouragent-mcp
    env:
      AYA_CLOUD: "https://authyouragent.com"
      AYA_AGENT_ID: "ag_xxxxx"
      AYA_KEY_FILE: "/path/to/agent-key.pem"
```

### Claude Desktop

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_CLOUD": "https://authyouragent.com",
        "AYA_AGENT_ID": "ag_xxxxx",
        "AYA_KEY_FILE": "/path/to/agent-key.pem"
      }
    }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_CLOUD": "https://authyouragent.com",
        "AYA_AGENT_ID": "ag_xxxxx",
        "AYA_KEY_FILE": "/path/to/agent-key.pem"
      }
    }
  }
}
```

## Agent

```
python -m authyouragent keygen --name "Job-search assistant"
```

Register the printed `jwk` in the app (Agents -> Add an agent). Keep `privkey_pem` on the agent's machine.

```python
from authyouragent import AgentClient

agent = AgentClient(base_url="https://authyouragent.com", agent_id="ag_…",
                    privkey_pem=open("agent-key.pem").read())
agent.ensure_grant("jobs.example.com", scopes=["list", "apply"])   # phone approval
r = agent.request("GET", "https://jobs.example.com/api/jobs")
r = agent.request("POST", "https://jobs.example.com/api/jobs/j1/apply", stepup_action="apply")
```

## Site

```python
from authyouragent import SiteVerifier, AuthError

verifier = SiteVerifier("https://authyouragent.com", expected_audience="jobs.example.com",
                        public_base_url="https://jobs.example.com")

@app.get("/api/jobs")
def jobs(request: Request):
    try:
        auth = verifier.verify(request)
    except AuthError as e:
        raise HTTPException(401, {"error": e.error})
    ...
```

See `examples/` for a complete agent and a complete FastAPI site.

## Licence

MIT
