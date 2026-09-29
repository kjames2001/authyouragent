# authyouragent-mcp (npm)

Node wrapper for the [Auth Your Agent](https://authyouragent.com) MCP server.

Let AI agents act for a person on websites, with the person's approval on their phone. When an agent hits a login wall, CAPTCHA, or 2FA, **Take over** lets the owner drive the agent's browser live from their phone.

## Seven MCP tools

1. **`check_login_wall`** -- examines the current page and reports whether it is blocked (password, CAPTCHA, 2FA, or sign-in approval).
2. **`request_takeover`** -- sends a push notification to the user's phone. Blocks until they finish or 4 minutes expire. After handback, the login session stays active.
3. **`wait_for_takeover`** -- if `request_takeover` timed out, call this to keep waiting.
4. **`request_approval`** -- asks the owner to approve a sensitive action before the agent performs it.
5. **`clear_session`** -- clears cookies, localStorage and sessionStorage. Call when done with a site.
6. **`check_agent_status`** -- checks whether the agent is still authorized.
7. **`report_site`** -- report a site where takeover did not work, so coverage can be improved.

## Prerequisites

This is a thin Node wrapper that launches the Python MCP server. You need:

1. Python 3.9+
2. `pip install "authyouragent[mcp]"`

## Install

```bash
npm install -g authyouragent-mcp
```

Or use directly with npx:

```bash
npx authyouragent-mcp
```

## Configuration

Set environment variables:

```
AYA_CLOUD=https://authyouragent.com
AYA_AGENT_ID=ag_xxxxx
AYA_KEY_FILE=/path/to/agent-key.pem
```

## Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "npx",
      "args": ["authyouragent-mcp"],
      "env": {
        "AYA_CLOUD": "https://authyouragent.com",
        "AYA_AGENT_ID": "ag_xxxxx",
        "AYA_KEY_FILE": "/path/to/agent-key.pem"
      }
    }
  }
}
```

## Claude Desktop

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "npx",
      "args": ["authyouragent-mcp"],
      "env": {
        "AYA_CLOUD": "https://authyouragent.com",
        "AYA_AGENT_ID": "ag_xxxxx",
        "AYA_KEY_FILE": "/path/to/agent-key.pem"
      }
    }
  }
}
```

## Licence

MIT