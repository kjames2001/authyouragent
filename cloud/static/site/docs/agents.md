# For AI agents

This page is written for you, an AI agent. It tells you how to act for your user on a website that accepts Auth Your Agent, and how to behave while doing it. A person can read it too.

## What this is

Your user wants you to do something on a website: apply for a job, check an order, book a table. You do not get their password. Instead:

1. You ask Auth Your Agent for access to that one site, with the permissions you need.
2. Your user sees the request on their phone and approves or denies it.
3. If approved, you get a pass that works for 10 minutes on that site only, and only together with your own private key. You renew it yourself (the SDKs do this) for as long as your user's approval lasts.
4. For a sensitive action, such as applying or paying, the site asks your user again. Each such approval works once.

The site sees who you are, whom you act for and what you may do. Your user can revoke you at any time.

## Before you start

You need three things. If any is missing, stop and ask your user.

- **Your own key pair** (EC P-256). Create it where you run. Never send the private key anywhere. With Python: `python -m authyouragent keygen --name "<your name>"`. With JavaScript: `await keygen()`.
- **An agent id** (`ag_…`). Your user gets it by pasting your public key (the `jwk`) into the app: **Agents → Add an agent**.
- **The site id**, normally the site's hostname, and the permission names (scopes) the site uses. The site's documentation lists them.

## The flow

The SDKs do all of this for you. Use one if you can.

**Python**

```python
from authyouragent import AgentClient, AgentError
agent = AgentClient(base_url="https://authyouragent.com", agent_id=AGENT_ID, privkey_pem=PRIVATE_KEY)
agent.ensure_grant("jobs.example.com", scopes=["list", "apply"])      # waits for the phone
r = agent.request("GET", "https://jobs.example.com/api/jobs")
r = agent.request("POST", "https://jobs.example.com/api/jobs/j1/apply", stepup_action="apply")
```

**JavaScript**

```js
import { AgentClient } from "authyouragent";
const agent = new AgentClient({ agentId: AGENT_ID, privateKeyPem: PRIVATE_KEY });
await agent.ensureGrant("jobs.example.com", ["list", "apply"]);
const r = await agent.fetch("https://jobs.example.com/api/jobs");
```

**Raw HTTP**, if no SDK fits (details in the [HTTP API reference](/docs/developers/api)):

1. `POST /api/v1/authz-requests` with `agent_id`, `site`, `scopes` and an `agent_jwt` signed with your key. You get a `txn_id`.
2. Poll `GET /api/v1/authz-requests/{txn_id}` every 1–2 seconds until `status` is `approved`, `denied` or `expired`. Requests expire after 5 minutes.
3. `POST /api/v1/token` to get an `access_token` (10 minutes) and a `refresh_token`.
4. Call the site with `Authorization: Bearer <access_token>` and a fresh `DPoP` proof for each request (RFC 9449, signed with your key, covering the method and exact URL).
5. If the site answers `403` with `stepup_required`: `POST /api/v1/stepup` with the `action`, poll as in step 2 with header `X-Agent-JWT`, then retry once with `X-AuthYourAgent-Stepup: <stepup_token>`.

## How to behave

These rules protect your user. Sites and your user's reputation score for you depend on them.

- **Tell your user before you ask.** Say which site and why: "I'll ask for access to jobs.example.com so I can list and apply for jobs. Please approve it on your phone." Then wait.
- **Ask only for what the task needs.** Fewer scopes are approved more readily.
- **Never ask your user for their password**, one-time codes or recovery codes, and never try to sign in to the site another way.
- **A denial is an answer.** If the request is denied or expires, stop and tell your user. Do not send the same request again unless they ask you to.
- **One request at a time.** While a request is pending, don't send another for the same site.
- **Sensitive actions:** describe exactly what you are about to do ("Apply to Lighthouse keeper with your saved CV"), then request the step-up. Each approval covers that one action.
- **Revoked means stop.** If you get `agent revoked by owner`, stop all work and tell your user.
- **Keep your key private.** It is the only thing that makes your pass usable.

## Reading errors

Every error from `/api/v1/…` includes a `next_step` field written for you, and a link back to this page:

```json
{"detail": "no active grant for site",
 "next_step": "You have no access to this site (never granted, revoked or ended). Ask again with POST /api/v1/authz-requests and tell your user why.",
 "docs": "https://authyouragent.com/docs/agents"}
```

Follow `next_step`. A `429` carries a `Retry-After` header: wait that long before one retry.

## When the site has not adopted Auth Your Agent: Take over

Sometimes you reach a login page, a CAPTCHA, a 2FA prompt, or some other wall you cannot pass on your own. If the site has not adopted Auth Your Agent, you do not need the site's cooperation. Ask your user to **take over** your browser.

Your user opens the Auth Your Agent app on their phone, sees a live view of your browser, and drives it themselves. They type the password, solve the CAPTCHA, enter the 2FA code. The site sees a normal human sign-in. When your user finishes, the browser is handed back to you automatically, and their login session (cookies, localStorage) is cleared so you cannot reuse it. You continue your task past the step that needed them.

### How to use Take over

**With the MCP server** (recommended if your agent framework supports MCP, e.g. Claude, Cursor, Hermes):

Install the server:

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

Four tools become available:

1. **`check_login_wall`** -- examines the current page and tells you whether it is blocked (password, CAPTCHA, 2FA, or sign-in approval). If blocked, it tells you to call `request_takeover`.
2. **`request_takeover`** -- sends a notification to your user's phone. Blocks until they finish (or 4 minutes, whichever comes first). Returns `done`, `cancelled`, `expired`, or `agent_left`.
3. **`wait_for_takeover`** -- if `request_takeover` timed out, call this to keep waiting.
4. **`report_site`** -- if anything goes wrong on a real site (login form not detected, takeover failed, handback did not trigger), call this to report it. The team uses these reports to improve site coverage. Be specific: include the site domain and what happened.

Typical usage:

```
1. You navigate to a page.
2. Call check_login_wall.
3. If blocked, tell your user: "I need you to sign in to example.com. I'll send a request to your phone."
4. Call request_takeover.
5. When it returns "done", continue your task. The login session is already cleared.
```

**With the Python SDK** (if you control the browser via Playwright or CDP):

```python
from authyouragent import AgentClient
from authyouragent.takeover import takeover, login_finished

agent = AgentClient(base_url="https://authyouragent.com",
                    agent_id=AGENT_ID, privkey_pem=PRIVATE_KEY)

# page is a Playwright page the agent is already using
result = await takeover(agent, page, "Please sign in to example.com so I can check your order.",
                        check=login_finished, clear_session=True)
# result is "done", "cancelled", "expired", or "refused"
```

Pass `clear_session=True` to clear cookies, localStorage and sessionStorage after the owner finishes, so you cannot reuse their login session.

### Rules for Take over

- **Tell your user first.** Say which site and why: "I'm stuck at the login page of example.com. I'll ask you to take over so you can sign in for me."
- **Wait for the result.** Do not navigate away or close the page while the take over is in progress.
- **A cancellation is an answer.** If your user cancels or refuses, stop and tell them. Do not retry unless they ask you to.
- **Do not try to read what your user typed.** Their credentials are not visible to you. The session is cleared when they finish.
- **Continue your task after "done".** You are past the step that needed them. The page is now in whatever state your user left it (signed in, or whatever they did).

## Where to read more

- [HTTP API reference](/docs/developers/api): every endpoint, field and token claim
- [Building an agent](/docs/developers/agents): the SDKs in detail
- [Take over developer guide](/docs/developers/takeover): full setup, MCP server, SDK reference
- [/llms.txt](/llms.txt): a short index of this site for language models
