# authyouragent-mcp (npm)

Node wrapper for the [Auth Your Agent](https://authyouragent.com) MCP server,
for MCP clients that prefer `npx`.

Let AI agents act for a person on websites, with the person's approval on
their phone. The agent's browser runs in a vault it cannot read into; when a
site asks for a password, a CAPTCHA or 2FA, the owner takes over from their
phone.

## Prerequisites

This wrapper launches the Python MCP server. You need Python 3.9+ and Docker:

```bash
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_xxxxx --key /path/to/agent-key.pem
```

## MCP tools

- **Browser:** `navigate`, `click`, `type_text`, `read_page`. Clicks that
  submit, send, delete, pay or publish wait for the owner's approval.
- **`check_login_wall`**: is the page asking for a password, a code or a
  sign-in approval?
- **`request_takeover`** / **`wait_for_takeover`**: the owner takes over from
  their phone; the vault hands back once they have signed in.
- **`request_approval`**: ask the owner to approve an action.
- **`notify_owner`**: a one-way note to the owner's phone ("done", "stuck").
- **`end_session`**: sign out of every site used, then destroy the browser
  profile.
- **`check_agent_status`**: is the agent still authorized?
- **`report_site`**: report a site where take over did not work.

## Cursor / Claude Desktop

Cursor: `~/.cursor/mcp.json`. Claude Desktop: `claude_desktop_config.json`.

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "npx",
      "args": ["authyouragent-mcp"],
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

See the [vault guide](https://github.com/kjames2001/authyouragent/blob/main/vault/README.md)
for what protects what, and the known limits.

## Licence

MIT
