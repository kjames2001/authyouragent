---
name: authyouragent-takeover
description: Use when an agent hits a login, CAPTCHA, 2FA, or approval wall on a website. Lets the owner take over the browser from their phone, approve sensitive actions, and control agent access.
version: 2.0.0
author: Auth Your Agent
license: MIT
---

# Auth Your Agent — Take Over

**Use when** you (an AI agent) are stuck at a login page, CAPTCHA, 2FA prompt, or need approval for a sensitive action on a website. Your owner drives the browser from their phone, then hands it back to you.

## Prerequisites

Your owner sets this up once, on a machine with Docker:

```bash
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_your_agent_id --key /path/to/your-agent-key.pem
```

`vault up` starts the vault (a sandboxed browser on `127.0.0.1:7801`) and prints the MCP settings:

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_AGENT_ID": "ag_your_agent_id",
        "AYA_KEY_FILE": "/path/to/your-agent-key.pem",
        "AYA_VAULT_URL": "http://127.0.0.1:7801",
        "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"
      }
    }
  }
}
```

- **Agent ID** (`ag_...`): your owner creates it in the Auth Your Agent app.
- **Key file**: your EC P-256 private key, from `python -m authyouragent keygen --name "your name"`.

You drive the vault's browser only through the tools below. You never hold its cookies.

## Tools

### Browsing: navigate, click, type_text, read_page

```
navigate(url: "https://example.com/account")
read_page()                                   // URL, title, visible text; no screenshot needed
click(selector: "text=Orders")
type_text(selector: "#search", text: "order 1234", submit: true)
```

- Only public websites open. Local and private addresses are refused.
- A click (or Enter) that would submit, send, delete, pay or publish first asks your owner on their phone and waits. If they deny it, the tool says so and nothing happens. Sign-in forms are not interrupted.
- Never type your owner's passwords or codes. Ask for a take over instead.

### check_login_wall

**When:** After navigating to a page, before interacting with it.

Returns `blocked: yes` (with the type of wall: password, CAPTCHA, one-time code, sign-in approval) or `blocked: no`. If blocked, tell your user, then call `request_takeover`.

### request_takeover

**When:** You are blocked and need your owner to sign in, solve a CAPTCHA, or enter a 2FA code.

```
request_takeover(
  reason: "Please sign in to example.com so I can check your order",
  wait_seconds: 240  // optional
)
```

Your owner's phone shows the vault's screen and they drive it. You are disconnected while they are in control. Once they have signed in, the vault hands the browser back automatically.

Returns `done`, `cancelled`, `expired` or `incomplete`, each with a line saying what to do next, or `waiting` with a `takeover_id`.

**After `done`:** continue on the logged-in page. Do not sign in again.

### wait_for_takeover

**When:** `request_takeover` returned `waiting`.

```
wait_for_takeover(takeover_id: "tk_...")
```

### request_approval

**When:** You are about to do something sensitive that the vault cannot see for itself: an action outside the browser, or a button whose wording does not show what it does.

```
request_approval(site: "github.com", action: "delete repository test-repo")
```

Returns `approved`, `denied` or `expired`. Do not act until `approved`.

### end_session

**When:** You are done. Always call it.

Signs out of every site you used, confirms it where it can, then destroys the browser profile. The result lists each site; if a site says "wiped locally, not signed out", tell your owner which one so they can end that session from the site's own device list.

### check_agent_status

**When:** Before starting a task, and during long tasks. Returns `active` or `revoked` (stop all work).

### report_site

**When:** Take over did not work on a site (form not detected, hand-back did not trigger, sign-out failed).

```
report_site(site: "example.com", kind: "handback_failed", detail: "what happened")
```

Kinds: `shadow_dom`, `bot_detection`, `input_not_detected`, `takeover_failed`, `handback_failed`, `session_not_cleared`, `other`. Never include credentials or personal data.

## Typical workflow

```
1. check_agent_status()
2. navigate(url), then check_login_wall()
3. If blocked:
   a. Tell your user: "I'm stuck at the sign-in page of example.com.
      I'll ask you to take over so you can sign in for me."
   b. request_takeover(reason="Please sign in to example.com")
   c. When it returns "done", continue with navigate / click / type_text / read_page.
4. end_session() when you are done.
```

## Rules

- **Tell your user before you ask.** Say which site and why.
- **Never ask for passwords, codes, or credentials.** Your owner types them during a take over.
- **A denial or cancellation is an answer.** Stop and tell your user. Do not retry unless they ask.
- **One take over at a time.**
- **Always call `end_session`** when you are done, and pass on any site it could not sign out of.
- **Revoked means stop.**
- **Report what breaks** with `report_site`.

## Privacy

- Your owner's credentials never pass through you. You cannot see what they type.
- The session stays in the vault on your owner's machine. You never hold the cookies.
- When the task ends, when you stop sending heartbeats, or when you are revoked, the vault signs out first, then wipes.
- Site reports contain only the site and what went wrong.

## Links

- [Website](https://authyouragent.com)
- [GitHub](https://github.com/kjames2001/authyouragent)
- [Vault guide](https://github.com/kjames2001/authyouragent/blob/main/vault/README.md)
- [Agent docs](https://authyouragent.com/docs/agents)
