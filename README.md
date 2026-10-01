# Auth Your Agent

An open-source MCP server that lets an AI agent act for a person on websites, with the person's approval on their phone.

The agent drives a sandboxed browser (the **vault**) that runs on the person's own machine. When a site asks for a password, a CAPTCHA or a 2FA code, the person takes over that browser from their phone, signs in, and hands it back. The agent never sees the password and never holds the cookies. When the task is done, the vault signs out of every site it used, then destroys the browser profile.

Website: [authyouragent.com](https://authyouragent.com) · License: [MIT](LICENSE)

## What is in this repository

The MCP server, the browser vault and the SDKs:

| Path | What it is |
|---|---|
| [`sdk/authyouragent/mcp_server.py`](sdk/authyouragent/mcp_server.py) | **The MCP server** (stdio, 11 tools). Entry point `authyouragent-mcp`. |
| [`vault/`](vault/) | **The browser vault**: [`broker.py`](vault/broker.py) (HTTP API the MCP server calls; drives Chromium, detects sign-in, signs out), [`egress.py`](vault/egress.py) (public-internet-only proxy), [`screen.py`](vault/screen.py) (phone screen stream), [`seccomp.json`](vault/seccomp.json), [`chromium-policy.json`](vault/chromium-policy.json), [`Dockerfile`](vault/Dockerfile). Details: [vault/README.md](vault/README.md). |
| [`sdk/authyouragent/vault_cli.py`](sdk/authyouragent/vault_cli.py) | `authyouragent vault up/down/status/env`: runs the vault with every protection on. |
| [`sdk/authyouragent/`](sdk/authyouragent/) | Python SDK: agent side ([`agent.py`](sdk/authyouragent/agent.py)), website side ([`site.py`](sdk/authyouragent/site.py)), take-over helper for your own Playwright browser ([`takeover.py`](sdk/authyouragent/takeover.py)). |
| [`sdk-js/`](sdk-js/) | JavaScript SDK, and [`npm-wrapper/`](sdk-js/npm-wrapper/) so Node clients can start the MCP server with `npx authyouragent-mcp`. |
| [`Dockerfile`](Dockerfile) | Container for the MCP server alone. |

The phone app and the approval service run at authyouragent.com. The agent signs its requests with its own key pair; the service never receives the person's passwords.

## MCP tools

| Tool | What it does |
|---|---|
| `navigate`, `click`, `type_text`, `read_page` | Drive the vault's browser. Only public websites open. Clicks that submit a form, or whose button says create, send, save, delete, pay and the like, ask the owner's phone first. |
| `check_login_wall` | Is the page blocked by a password, CAPTCHA, one-time code or sign-in approval? Reads the page's fields and text, so the model needs no vision. |
| `request_takeover` | Ask the owner to take over the browser from their phone. Returns `done`, `cancelled`, `expired`, `incomplete`, or `waiting`. |
| `wait_for_takeover` | Keep waiting after `waiting`. |
| `request_approval` | Ask the owner to approve an action. `approved`, `denied` or `expired`. |
| `end_session` | Sign out of every site used, then destroy the browser profile. Reports per site whether sign-out was confirmed. |
| `check_agent_status` | `active` or `revoked`. |
| `report_site` | Report a site where take over did not work. |

## Run it

From PyPI:

```bash
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_... --key /path/to/agent-key.pem
```

From this repository:

```bash
git clone https://github.com/kjames2001/authyouragent && cd authyouragent
pip install "./sdk[mcp]"
docker build -f vault/Dockerfile -t authyouragent/vault:local .
authyouragent vault up --agent-id ag_... --key /path/to/agent-key.pem --image authyouragent/vault:local --no-pull
```

The vault needs Docker. `vault up` prints the MCP settings to add to your client:

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_AGENT_ID": "ag_...",
        "AYA_KEY_FILE": "/path/to/agent-key.pem",
        "AYA_VAULT_URL": "http://127.0.0.1:7801",
        "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"
      }
    }
  }
}
```

Node clients can use `npx authyouragent-mcp` as the command. The agent ID and key come from adding the agent in the phone app (**Agents > Add an agent**). Without them the server still starts and lists its tools; each tool then says what is missing.

## Security

- Chromium's own sandbox is on (custom seccomp profile, all container capabilities dropped); gVisor is used automatically when Docker has the `runsc` runtime.
- The browser can reach only the public internet: loopback, private networks, cloud metadata addresses and the vault's own ports are refused, checked on the resolved address.
- The agent is disconnected while the owner is in control, and cannot read the browser's cookies.
- Sign out first, wipe second: at the end of a session, when the agent stops sending heartbeats, or when it is revoked. Sites the vault could not sign out of are reported to the owner, also after a crash.

Known limits are listed in [vault/README.md](vault/README.md).

## Documentation

- [For AI agents](https://authyouragent.com/docs/agents)
- [Take over developer guide](https://authyouragent.com/docs/developers/takeover)
- [Developer quickstart](https://authyouragent.com/docs/developers/quickstart)
- [How it works](https://authyouragent.com/how-it-works)

## Android app

Download from [authyouragent.com/download/android](https://authyouragent.com/download/android).

## License

[MIT](LICENSE)
