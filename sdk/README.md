<!-- mcp-name: com.authyouragent.mcp -->
# authyouragent (Python)

SDK for [Auth Your Agent](https://authyouragent.com): let AI agents act for a person on websites, with the person's approval on their phone.

- `AgentClient`: an agent asks for access, then calls sites with a short-lived pass and a fresh DPoP proof (RFC 9449) on every request.
- `SiteVerifier`: a website checks each call in one line.
- **Browser vault**: the agent's browser runs in a container it cannot read into. When a site asks for a password, a CAPTCHA or 2FA, the owner takes over from their phone; clicks that commit something wait for the owner's approval.

Python 3.9+. Depends on `httpx`, `pyjwt`, `cryptography`.

Full documentation: https://authyouragent.com/docs/developers/quickstart

## Install

You need Python 3.9+ and Docker.

```
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_xxxxx --key /path/to/agent-key.pem
```

`vault up` starts the browser vault: the browser your agent uses, in a
container on your machine. The agent drives it through the vault and never
gets its cookies. It prints the `env` block for your MCP client. See
[vault/README.md](https://github.com/kjames2001/authyouragent/blob/main/vault/README.md)
for what protects what, and the known limits.

For just the SDK (no browser, no MCP): `pip install authyouragent`.

## MCP server

The `authyouragent-mcp` command starts an MCP server with eleven tools:

- **Browser:** `navigate`, `click`, `type_text`, `read_page`. Clicks that
  submit, send, delete, pay or publish wait for your approval on your phone.
- **`check_login_wall`**: is the page asking for a password, a code or a
  sign-in approval?
- **`request_takeover`** / **`wait_for_takeover`**: you take over the browser
  from your phone. The agent is disconnected until you finish, and the vault
  hands back by itself once you have signed in.
- **`request_approval`**: ask you to approve an action the vault cannot see.
- **`end_session`**: sign out of every site used, then destroy the browser
  profile. Always called at the end.
- **`check_agent_status`**: is the agent still authorized? You can revoke it
  at any time.
- **`report_site`**: report a site where take over did not work.

### Configuration

```
AYA_AGENT_ID=ag_xxxxx
AYA_KEY_FILE=/path/to/agent-key.pem
AYA_VAULT_URL=http://127.0.0.1:7801
AYA_VAULT_TOKEN_FILE=~/.authyouragent/vault/token
```

### Hermes

```yaml
mcp:
  authyouragent:
    enabled: true
    command: authyouragent-mcp
    env:
      AYA_AGENT_ID: "ag_xxxxx"
      AYA_KEY_FILE: "/path/to/agent-key.pem"
      AYA_VAULT_URL: "http://127.0.0.1:7801"
      AYA_VAULT_TOKEN_FILE: "~/.authyouragent/vault/token"
```

### Claude Desktop / Cursor

Claude Desktop: `claude_desktop_config.json`. Cursor: `~/.cursor/mcp.json`.

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_AGENT_ID": "ag_xxxxx",
        "AYA_KEY_FILE": "/path/to/agent-key.pem",
        "AYA_VAULT_URL": "http://127.0.0.1:7801",
        "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"
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
