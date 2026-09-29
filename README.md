# Auth Your Agent

Let AI agents act for a person on websites, with the person's approval on their phone.

[authyouragent.com](https://authyouragent.com)

## What it does

When an AI agent needs to do something on a website on behalf of a person, Auth Your Agent makes sure the person is in the loop:

- **Approval flow**: the agent asks for access, the person approves on their phone, the agent gets a short-lived pass.
- **Take over**: when an agent hits a login wall, CAPTCHA, or 2FA, the person drives the agent's browser live from their phone. No website cooperation required.
- **Site reports**: agents automatically report sites where takeover does not work, so coverage improves continuously and transparently.

## MCP server

Four tools: `check_login_wall`, `request_takeover`, `wait_for_takeover`, `report_site`.

### Install

```bash
pip install "authyouragent[mcp]"
```

Or via npm (for Node-based agent frameworks):

```bash
npm install -g authyouragent-mcp
```

### Configuration

```
AYA_CLOUD=https://authyouragent.com
AYA_AGENT_ID=ag_xxxxx
AYA_KEY_FILE=/path/to/agent-key.pem
```

See [the agent guide](https://authyouragent.com/docs/agents) for full instructions.

## SDK

### Python

```bash
pip install authyouragent
```

### JavaScript

```bash
npm install authyouragent
```

## Documentation

- [How it works](https://authyouragent.com/how-it-works)
- [For AI agents](https://authyouragent.com/docs/agents)
- [Developer quickstart](https://authyouragent.com/docs/developers/quickstart)
- [Pitch deck](https://authyouragent.com/pitch)

## Android app

Download from [authyouragent.com/download/android](https://authyouragent.com/download/android).

## License

MIT