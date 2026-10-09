# OpenClaw and Hermes Agent

[OpenClaw](https://openclaw.ai) and [Hermes Agent](https://github.com/NousResearch/hermes-agent) can both drive websites through your vault. You get two things from this setup:

- the agent reaches websites only through the vault;
- the agent waits while an approval is on your phone, instead of stopping to ask you to approve.

Both setups use the vault's MCP server, `authyouragent-mcp`. Start with the vault itself:

```sh
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_... --key /path/to/agent-key.pem
```

For browser-use and Goose, see [browser-use and Goose](/docs/developers/browser-use-goose).

`vault up` prints the values used below. `AYA_AGENT_ID` and the key come from **Agents → Add an agent** in the app. The env values are file paths and an id, not secrets. See [Take over](/docs/developers/takeover) for a vault on another machine.

## OpenClaw

Tested with OpenClaw 2026.9.9.

### 1. Add the vault and turn off OpenClaw's own web tools

In `~/.openclaw/openclaw.json`:

```json
{
  "browser": { "enabled": false },
  "plugins": { "entries": { "browser": { "enabled": false } } },
  "tools": {
    "profile": "minimal",
    "alsoAllow": ["bundle-mcp"],
    "deny": ["browser", "web_fetch", "web_search", "exec", "process"]
  },
  "mcp": {
    "servers": {
      "authyouragent": {
        "command": "authyouragent-mcp",
        "env": {
          "AYA_AGENT_ID": "ag_...",
          "AYA_KEY_FILE": "/path/to/agent-key.pem",
          "AYA_VAULT_URL": "http://127.0.0.1:7801",
          "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"
        },
        "requestTimeoutMs": 320000
      }
    }
  }
}
```

Merge this into your own config. Leave out `exec` and `process` from `deny` if the agent needs a shell for other work. Without a shell, nothing on the machine can reach a website except the vault.

- `alsoAllow: ["bundle-mcp"]` is needed: the `minimal` profile does not include MCP tools, and without it the agent never sees the vault.
- `requestTimeoutMs` must be longer than an approval wait (about 5 minutes), or OpenClaw drops the call while you are deciding.

Check it: `openclaw mcp probe authyouragent` lists the vault's tools.

### 2. Install the skill

```sh
openclaw skills install @kjames2001/authyouragent --global
```

The skill tells the agent to use the vault for every website and to keep waiting while a card is on your phone. Without it, models tend to end their turn at each approval and ask you to approve, then wait for you to tell them you did. `openclaw skills list` shows it as ready once the `authyouragent` server is configured.

### 3. Try it

```sh
openclaw agent -m "Buy me the Brass lighthouse lamp from https://demo.authyouragent.com and tell me if the order went through."
```

[Demo Shop](https://demo.authyouragent.com) charges nothing. Your phone gets the cards in turn: the sign-in, the vault's check on Buy, then the shop's own payment request. The agent reports the order as paid after the last tap.

## Hermes Agent

The [hermes-authyouragent](https://github.com/kjames2001/hermes-authyouragent) plugin (MIT) does three things:

- blocks Hermes's built-in `browser_*` tools while the vault's MCP server is configured;
- adds a prompt section telling the agent to wait for your approvals;
- adds the skill `authyouragent:authyouragent`.

### 1. Add the vault's MCP server

```sh
hermes mcp add authyouragent --command authyouragent-mcp --env \
  AYA_VAULT_URL=http://127.0.0.1:7801 \
  AYA_VAULT_TOKEN_FILE=~/.authyouragent/vault/token \
  AYA_AGENT_ID=ag_... \
  AYA_KEY_FILE=/path/to/agent-key.pem
```

Answer `y` to enable all its tools.

### 2. Install the plugin

```sh
hermes plugins install kjames2001/hermes-authyouragent --enable
```

Start a new session. A call to `browser_navigate` now returns a message pointing the model to the vault tools. If you remove or disable the `authyouragent` MCP server, the plugin steps aside and the built-in browser works as before.

Settings, under `plugins.entries.authyouragent.settings`:

- `server_name`: the `mcp_servers` entry that runs `authyouragent-mcp` (default `authyouragent`).
- `block_builtin_browser`: `false` keeps the built-in browser available alongside the vault (default `true`).

### 3. Try it

```sh
hermes chat -q "Buy me the Brass lighthouse lamp from https://demo.authyouragent.com and tell me if the order is paid."
```

## What this does not cover

- Turning off an agent's own web tools keeps the model on the vault. It does not stop other software on the same machine from reaching the web.
- An agent running as root, or as the vault's user, can read the vault's files. To keep them out of its reach, run the vault on another machine ([Take over: the vault on another machine](/docs/developers/takeover)).
