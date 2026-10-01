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

Your browser runs in your user's **vault**: a sandboxed browser on their machine that you drive through tools. You never hold its cookies. When you ask for a take over, your user's phone shows the vault's screen and they drive it themselves: they type the password, solve the CAPTCHA, enter the 2FA code. The site sees a normal human sign-in. You are disconnected while they are in control. Once they have signed in, the vault hands the browser back to you on its own, and you continue on the logged-in page. When you are done, you end the session: the vault signs out of every site you used, then destroys the browser profile.

### Set up (your user does this once)

```bash
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_your_agent_id --key /path/to/your-agent-key.pem
```

The vault needs Docker. `vault up` prints the settings for your MCP configuration:

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

Node-based MCP clients can use `"command": "npx", "args": ["authyouragent-mcp"]` with the same settings.

### Your tools

- **`navigate(url)`**, **`click(selector)`**, **`type_text(selector, text, submit)`**, **`read_page()`**: drive the vault's browser. Only public websites open; a local or private address returns "blocked by the vault". A click (or Enter) that submits a form, or whose button says create, send, save, delete, pay and the like, first asks your user on their phone and waits; if they deny it, the tool returns an error and nothing happens. Search boxes and sign-in steps are not interrupted.
- **`check_login_wall`**: is the page asking for a password, a CAPTCHA, a code or a sign-in approval? If yes, it tells you to call `request_takeover`.
- **`request_takeover(reason)`**: asks your user to take over. Returns `done`, `cancelled`, `expired` or `incomplete`, each with a line saying what to do next, or `waiting` with a `takeover_id` if your user needs longer.
- **`wait_for_takeover(takeover_id)`**: keeps waiting after `waiting`.
- **`request_approval(site, action)`**: asks your user to approve an action before you do it, when the vault cannot see it for itself.
- **`end_session`**: signs out of every site you used, then destroys the browser profile. It says, per site, whether sign-out was confirmed. Always call it when you are done.
- **`check_agent_status`**: are you still authorized? Your user can revoke you at any time.
- **`report_site`**: tell the team about a site where take over did not work. Include the site and what happened.

Typical usage:

```
1. check_agent_status.
2. navigate to the page, then check_login_wall.
3. If blocked, tell your user: "I need you to sign in to example.com. I'll send a request to your phone."
4. request_takeover. When it returns "done", continue with navigate, click, type_text, read_page.
5. end_session when you are done.
```

**Driving your own browser instead** (developers): the Python and JavaScript SDKs also have a `takeover()` helper for a Playwright page you control. The vault is safer, because an agent that holds its own browser can read the session it was given. See the [Take over developer guide](/docs/developers/takeover).

### Rules for Take over

- **Tell your user first.** Say which site and why: "I'm stuck at the login page of example.com. I'll ask you to take over so you can sign in for me."
- **Never ask for passwords or codes.** Ask for a take over instead.
- **Wait for the result.** Do not act while the take over is in progress.
- **A cancellation or a denial is an answer.** Stop and tell your user. Do not retry unless they ask you to.
- **Always call `end_session`** when you are done. It signs your user out of the sites you used; if the vault could not sign out of a site, tell your user which one.
- **Revoked means stop.**

## Where to read more

- [HTTP API reference](/docs/developers/api): every endpoint, field and token claim
- [Building an agent](/docs/developers/agents): the SDKs in detail
- [Take over developer guide](/docs/developers/takeover): full setup, MCP server, SDK reference
- [/llms.txt](/llms.txt): a short index of this site for language models
