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
gets its cookies. It prints the `env` block for your MCP client. If you skip
it, the MCP server starts the vault itself the first time the agent needs the
browser (`AYA_VAULT_AUTOSTART=0` turns that off). See
[vault/README.md](https://github.com/kjames2001/authyouragent/blob/main/vault/README.md)
for what protects what, and the known limits.

For just the SDK (no browser, no MCP): `pip install authyouragent`.

## MCP server

The `authyouragent-mcp` command starts an MCP server with twenty tools:

- **Browser:** `navigate`, `read_page` (the page's text plus a numbered list
  of links, buttons, fields and dropdowns), and `click`, `type_text`,
  `select_option`, `press_key` by that number. `scroll`, `go_back`,
  `wait_for`, `screenshot`. Only public websites open. Anything that submits
  a form, or whose button says create, send, save, delete, pay and the like,
  waits for your approval on your phone.
- **Approval modes** (in the app, per agent and site): Ask, Smart or Off.
  Smart lets changes you can undo (save, filter, add to cart) through without
  asking; money, deleting, posting and account changes always ask. Rules
  only, no AI. The approval card shows the amount and item read from the
  page, and the vault will not click if the amount changed after you approved.
- **Trusted sites:** `authyouragent vault trust example.com --no-approvals`
  stops per-click approvals on a site you use often;
  `authyouragent vault trust 192.168.1.20:8123 --private` lets the browser
  open one host on your own network. Each entry asks your phone once per
  session before it applies.
- **`check_login_wall`**: is the page asking for a password, a code or a
  sign-in approval?
- **`list_secrets`** / **`fill_secret`**: fill a username, password or
  authenticator code from your own Bitwarden or Vaultwarden (only the items in
  its "Auth Your Agent" folder). The agent never sees the value; it fills only
  on the item's own site and only the right kind of field.
- **`request_takeover`** / **`wait_for_takeover`**: you take over the browser
  from your phone. The agent is disconnected until you finish, and the vault
  hands back by itself once you have signed in.
- **`request_approval`**: ask you to approve an action the vault cannot see.
- **`notify_owner`**: a one-way note to your phone, e.g. "done" or "stuck".
  Nothing to approve.
- **`end_session`**: sign out of every site used, then destroy the browser
  profile. Always called at the end. The vault then sends you its own summary
  of the session, whether or not the agent sent a note.
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

Gate a script or CI step on your phone. The command exits 0 only if you approve:

```
export AYA_AGENT_ID=ag_xxxxx AYA_KEY_FILE=/path/to/agent-key.pem
authyouragent approve npmjs.com publish && npm publish
```

Exit codes: 0 approved, 1 denied, 2 could not ask (key, revoked, network), 3 no answer in time. From Python: `agent.request_approval("npmjs.com", "publish")`.

Tell your phone when an unattended job ends (one-way, nothing to approve):

```
make deploy; authyouragent notify "deploy finished with exit code $?"
```

Exit codes: 0 delivered, 1 recorded but no device has notifications on, 2 could not send. From Python: `agent.notify("done")`.

```python
from authyouragent import AgentClient

agent = AgentClient(base_url="https://authyouragent.com", agent_id="ag_…",
                    privkey_pem=open("agent-key.pem").read())
agent.ensure_grant("jobs.example.com", scopes=["list", "apply"])   # phone approval
r = agent.request("GET", "https://jobs.example.com/api/jobs")
r = agent.request("POST", "https://jobs.example.com/api/jobs/j1/apply", stepup_action="apply")
```

Sites with a **Sign in with Auth Your Agent** button (OpenID Connect): the vault handles it on its own when the agent clicks the button. Without the vault:

```python
back = agent.oidc_signin(authorize_url)   # the site's /oidc/authorize link; waits for the phone if needed
http.get(back)                            # finish on the site's own callback
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
