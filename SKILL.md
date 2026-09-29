---
name: authyouragent-takeover
description: Use when an agent hits a login, CAPTCHA, 2FA, or approval wall on a website. Lets the owner take over the browser from their phone, approve sensitive actions, and control agent access.
version: 1.0.0
author: Auth Your Agent
license: MIT
---

# Auth Your Agent — Take Over

**Use when** you (an AI agent) are stuck at a login page, CAPTCHA, 2FA prompt, or need approval for a sensitive action on a website. Your owner drives the browser from their phone, then hands it back to you.

## Prerequisites

Install the MCP server:

```bash
pip install "authyouragent[mcp]"
```

Register it with your agent framework. For example, in your MCP config:

```json
{
  "mcpServers": {
    "authyouragent": {
      "command": "authyouragent-mcp",
      "env": {
        "AYA_CLOUD": "https://authyouragent.com",
        "AYA_AGENT_ID": "ag_your_agent_id",
        "AYA_KEY_FILE": "/path/to/your-agent-key.pem"
      }
    }
  }
}
```

You need:
- **An agent ID** (`ag_...`) — your owner creates this in the Auth Your Agent app
- **A key file** — your EC P-256 private key, generated with `python -m authyouragent keygen --name "your name"`
- **A Chromium browser** running with `--remote-debugging-port=9222` (the MCP server auto-discovers it)

## Seven Tools

### 1. check_login_wall

**When:** After navigating to a page, before interacting with it.

Checks whether the current page is blocked by a login form, CAPTCHA, 2FA code, or sign-in approval. Returns `blocked: yes` (with the type of wall) or `blocked: no` (with the page title and URL).

```
check_login_wall()
```

If blocked, tell your user what you found, then call `request_takeover`.

### 2. request_takeover

**When:** You are blocked and need your owner to sign in, solve a CAPTCHA, or enter a 2FA code.

Sends a push notification to your owner's phone. They see a live view of your browser and drive it themselves. They type the password, solve the CAPTCHA, enter the 2FA code. The website sees a normal human interaction. When they finish, the browser is handed back to you automatically.

```
request_takeover(
  reason: "Please sign in to example.com so I can check your order",
  wait_seconds: 240  // optional, default 240
)
```

Returns: `done`, `cancelled`, `expired`, `agent_left`, or `waiting` (with a `takeover_id` for `wait_for_takeover`).

**After `done`:** The owner's login session stays active. You can continue your task on the logged-in page. You do NOT need to sign in again.

**Important:** Do not navigate away or close the page while the takeover is in progress.

### 3. wait_for_takeover

**When:** `request_takeover` returned `waiting` and you want to keep waiting.

```
wait_for_takeover(
  takeover_id: "tk_..."  // from request_takeover
)
```

### 4. request_approval

**When:** You are about to do something sensitive — delete data, change settings, make a purchase, modify permissions, or any action with irreversible consequences.

Asks your owner to approve or deny the action on their phone. This is a simple approve/deny — the owner does not drive the browser. Do not perform the action until this returns `approved`.

```
request_approval(
  site: "github.com",
  action: "delete repository test-repo",
  wait_seconds: 120  // optional, default 120
)
```

Returns: `approved`, `denied`, or `expired`.

### 5. clear_session

**When:** You are done with a site after a takeover. This is the cleanup step.

Clears cookies, localStorage, and sessionStorage on the current page so you cannot reuse the owner's login session. The server logs this so the owner's dashboard shows the session was cleared.

```
clear_session()
```

**Always call this when you are finished with a site.** Do not leave the owner's session active after your task is complete.

### 6. check_agent_status

**When:** Before starting a new task, or periodically during long tasks.

Checks whether you are still authorized by the owner. The owner can revoke your access at any time from their phone.

```
check_agent_status()
```

Returns: `active` (with agent name and any revoked sites) or `revoked` (stop all work immediately).

### 7. report_site

**When:** Something went wrong during a takeover — the login form was not detected, the takeover failed, the handback did not trigger, or the session was not cleared.

Reports the issue to the Auth Your Agent team so they can improve site coverage. This is transparent and public — the team has nothing to hide.

```
report_site(
  site: "example.com",
  kind: "input_not_detected",  // shadow_dom, bot_detection, input_not_detected,
                                // takeover_failed, handback_failed,
                                // session_not_cleared, other
  detail: "The login form was inside a shadow DOM and check_login_wall did not detect it"
)
```

## Typical Workflow

```
1. Navigate to a page.
2. check_login_wall()
3. If blocked:
   a. Tell your user: "I'm stuck at the login page of example.com.
      I'll ask you to take over so you can sign in for me."
   b. request_takeover(reason="Please sign in to example.com")
   c. When it returns "done", continue your task on the logged-in page.
4. If you need to do something sensitive:
   a. request_approval(site="example.com", action="delete account")
   b. Only proceed if it returns "approved".
5. When you are done with the site:
   a. clear_session()
6. Before starting a new task:
   a. check_agent_status()
```

## Rules

- **Tell your user before you ask.** Say which site and why.
- **Never ask for passwords, codes, or credentials.** Your owner types them during takeover — you never see them.
- **A denial is an answer.** If denied or cancelled, stop and tell your user. Do not retry unless they ask.
- **One takeover at a time.** Do not start a second takeover while one is in progress.
- **Always clear_session when done.** Do not leave the owner's login session active.
- **Revoked means stop.** If `check_agent_status` returns `revoked`, stop all work and tell your user.
- **Report what breaks.** If a site does not work with takeover, call `report_site` so it can be fixed.

## How It Works

1. You navigate to a page in your browser (Chromium with `--remote-debugging-port=9222`).
2. `check_login_wall` reads the page's DOM (text, form fields, iframes) — no screenshots, so agents without vision can use it.
3. `request_takeover` sends a request to the Auth Your Agent server, which pushes a notification to your owner's phone.
4. Your owner opens the app, sees a live view of your browser at phone size, and interacts with it directly.
5. When they tap "Done", the server checks whether the page is no longer blocked (using the same DOM checks).
6. The browser is handed back to you. The page is in whatever state your owner left it (signed in, verified, etc.).
7. You continue your task. When done, you call `clear_session` to wipe the session.

## Privacy

- Your owner's credentials never leave their typing. You cannot see what they typed.
- The session (cookies, localStorage) stays active after handback so you can work, but you must clear it when done.
- The server logs agent status changes (takeover started, done, session cleared) for the owner's audit trail.
- Site reports do not include credentials or personal data — only the site domain and what went wrong.

## Links

- [Website](https://authyouragent.com)
- [GitHub](https://github.com/kjames2001/authyouragent)
- [Agent docs](https://authyouragent.com/docs/agents)
- [HTTP API reference](https://authyouragent.com/docs/developers/api)