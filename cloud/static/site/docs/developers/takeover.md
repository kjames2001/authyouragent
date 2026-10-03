# Take over: when your agent is stuck

Your agent reaches a login page, a CAPTCHA or a 2FA prompt that it cannot or must not get past on its own. Instead of failing the task, it asks its owner to take over. The owner's phone gets a notification and a live view of the agent's browser. They tap and type on the page as if it were their own browser, press the site's own Sign in button, and the agent continues.

The site does not need to support Auth Your Agent. It sees an ordinary person signing in.

## What the owner sees

1. A notification: "Auth Your Agent: <agent name> needs you", with the reason your agent gave.
2. A live view of the agent's browser, sized for a phone.
3. They tap and type on it as on their own phone: tapping a field brings up their keyboard, with its predictions and autofill. **Back** and **Start again** buttons sit above the page.
4. Once they have signed in, the view closes with **Done, handed back**. They can also press **Done** themselves at any time, or **Cancel**.

## Add it to your agent

### Any MCP agent: no code, with the vault

The safest way: the agent's browser runs in a **vault**, a sandboxed Chromium in a container on the owner's machine. The agent drives it through MCP tools and never holds its cookies. The owner's phone shows the vault's screen during a take over, and the agent is disconnected until they finish.

```sh
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_... --key /path/to/agent-key.pem
```

The vault needs Docker. `vault up` starts it on `127.0.0.1:7801` with every protection on, and prints the MCP settings. (If you skip `vault up`, the MCP server starts the vault itself the first time the agent needs the browser; `AYA_VAULT_AUTOSTART=0` turns that off.)

```json
{"mcpServers": {"authyouragent": {
  "command": "authyouragent-mcp",
  "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/to/agent-key.pem",
          "AYA_VAULT_URL": "http://127.0.0.1:7801",
          "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"}
}}}
```

`AYA_AGENT_ID` and the key come from adding the agent in the app (**Agents → Add an agent**). Node-based clients can use `npx authyouragent-mcp` instead of `authyouragent-mcp`.

The agent gets nineteen tools:

| Tool | Purpose |
|---|---|
| `navigate`, `read_page` | Open a page; read its text plus a numbered list of the links, buttons, fields, dropdowns and checkboxes on it (password values never shown). |
| `click`, `type_text`, `select_option`, `press_key` | Act on an element by its number from `read_page` (`ref`), or by CSS `selector`. Anything that commits something waits for the owner's approval. |
| `scroll`, `go_back`, `wait_for`, `screenshot` | Scroll (and load more on endless pages), go back, wait for text to appear or disappear, see the page as a JPEG. |
| `check_login_wall` | Is the page asking for a password, a CAPTCHA, a code or a sign-in approval? |
| `list_secrets` | The sign-ins the owner has shared from their password manager: names, sites and fields, never values. |
| `fill_secret(name, field, ref)` | Type a username, password or authenticator code from the owner's password manager into a field. The agent never sees the value. See [Saved sign-ins](#saved-sign-ins). |
| `request_takeover(reason)` | Ask the owner to take over. Returns `done`, `cancelled`, `expired` or `incomplete` with a line saying what to do next, or `waiting` with a `takeover_id` after `wait_seconds` (default 240). |
| `wait_for_takeover(takeover_id)` | Keep waiting after `waiting`. |
| `request_approval(site, action)` | Ask the owner to approve an action. `approved`, `denied` or `expired`. |
| `end_session` | Sign out of every site used, then destroy the browser profile. Reports per site whether sign-out was confirmed. |
| `check_agent_status` | `active` or `revoked`. |
| `report_site` | Report a site where take over did not work. |

The tools answer in plain text and read the page's fields and text, so the model driving your agent does not need vision; `screenshot` is there for models that have it.

What the vault enforces, whatever the agent does:

- **Step-up approval.** A click (or Enter, or Space) that submits a form, or on a button that says create, send, save, delete, pay, publish and the like, first asks the owner on their phone, showing the button's words. Any other click that makes the page write to the site within 2 seconds (a scripted POST, PUT, PATCH, DELETE or GraphQL mutation) is held until the owner approves. Search boxes and sign-in steps are not interrupted; "Authorize" and "Allow" on a sign-in page still ask. Add words with `VAULT_APPROVE_WORDS`.
- **Public internet only**, unless the owner trusts a host (below). Loopback, private networks, cloud metadata addresses and the vault's own ports are refused, checked on the resolved address.
- **Trusted sites are the owner's exceptions, never the agent's.** See [Trusted sites](#trusted-sites).
- **No internal browser pages**, `file://`, extensions, downloads or saved passwords.
- **Chromium's sandbox on**, all container capabilities dropped; under gVisor automatically when Docker has the `runsc` runtime.
- **Sign out first, wipe second.** At the end of a session, and when the agent stops sending heartbeats or is revoked, the vault signs out of each site, confirms it where it can, then destroys the in-memory profile. Sites it could not sign out of are reported to the owner, also after a crash.

## Approval modes

Every click that commits something (buy, post, delete, submit a form) waits for the owner's approval on their phone. The owner chooses, per agent and per site, how often that happens. In the app: **Agents → Approvals**.

| Mode | What asks |
|---|---|
| **Ask** (default) | Every committing click. |
| **Smart** | Only what matters. Changes the owner can undo in a click go through without asking: save, update settings, filter or sort, add to cart or a list, archive, mark as read, star, pin. Up to an hourly limit per site (20 by default, up to 200). |
| **Off** | Nothing on that site, except account and security changes. Only per site, never for all sites. |

Whatever the mode, these always ask:

- **money**: an amount on the button's form, card-number fields, or pay, buy, order, subscribe and similar wording;
- **deleting**: delete, remove, cancel, close, revoke;
- **acting as the owner**: post, send, comment, reply, share, invite, merge, deploy;
- **account and security**: password, email, two-factor, keys, permissions (these ask even on an Off site);
- **anything unclear**: an unlabelled button, or wording that is not on the low-risk list.

Smart also pauses on a site for an hour after the owner denies something there.

**Rules only.** Modes decide from the button's words, the form's fields, any amount, the site and the limits. There is no model involved, so every decision can be explained, and nothing a page says can talk its way past them. The agent cannot change its own mode: only the owner, signed in to the app, can.

**The approval card shows what the vault read from the page:** the amount, item and order number from the button's own form or section (not a total elsewhere on the page). Each approval is for that one action, works once, and expires after five minutes. If the amount changes between the approval and the click, the vault does not click and asks again. Activity lists every card with what it showed, every action that went through without asking and why, and every change of mode.

For the agent nothing changes: the click returns when it is approved, by the owner or by their mode, and fails with `the owner did not approve` otherwise.

## Trusted sites

The vault's rules suit most sites. For a site the owner uses all the time, or a service on their own network, they can relax them:

```bash
authyouragent vault trust example.com --no-approvals     # clicks on example.com stop asking each time (or set Off for the site in the app)
authyouragent vault trust 192.168.1.20:8123 --private    # the browser may open this host on your own network
authyouragent vault trust                                # list
authyouragent vault trust example.com --remove
```

- **Confirmed on the phone.** An entry does nothing until the owner approves it on their phone, once per session (until `end_session`). A changed entry asks again; a refused one is not asked again that session. An agent that writes to the file cannot use it on its own.
- **`--no-approvals`** covers the site and its subdomains. Saved passwords stay hidden from the agent; `read_page` still never shows password values.
- **`--private`** is one exact host and port, and only private ranges: 10/8, 172.16/12, 192.168/16, 100.64/10 (Tailscale) and IPv6 ULA. Loopback, link-local (cloud metadata) and the vault's own addresses stay blocked whatever the file says.
- The file is `~/.authyouragent/vault/trust/trusted.json`, mounted read-only into the vault. A vault started before 0.3.17 needs one `vault down` and `vault up` to see it.

## Saved sign-ins

For sites the agent signs in to often, a take over each time is too slow. The owner can instead share chosen sign-ins from their own **Bitwarden** or **Vaultwarden** with the vault. The agent asks the vault to fill a field; the vault types the value itself, and the agent never sees it. Authenticator codes work the same way: the vault computes the current code, and the key stays in the password manager.

Saved sign-ins are optional. Without a password manager the vault works as before, and `list_secrets` and `fill_secret` answer that none is set up. With one, take over is still how the agent gets past everything a stored value cannot:

- CAPTCHAs and "are you a robot" checks;
- sites with no item in the shared folder;
- codes sent by text message or email, and sign-in approvals on another device ("Check your phone");
- passkeys and security keys;
- sign-ins the owner prefers to do in person, such as banking.

1. In the password manager, make a folder named **Auth Your Agent** and move into it only the sign-ins the agent may use. Each item needs the site's address. Items outside the folder, and items owned by an organization, are never read.
2. Write a config file, readable only by you:

```json
{"url": "https://vault.bitwarden.com",
 "email": "you@example.com",
 "master_password": "...",
 "client_id": "user.xxxxxxxx", "client_secret": "..."}
```

`url` is your Vaultwarden address, or `https://vault.bitwarden.com` / `https://vault.bitwarden.eu`. The API key (**Account settings → Security → Keys → View API key**) is recommended, and needed if two-step login is on. The master password decrypts the items inside the vault and is never sent to the server.

3. `authyouragent vault up --agent-id ag_... --key agent.pem --bitwarden bitwarden.json`. Later starts reuse it. To stop using it, run `authyouragent vault down`, delete `~/.authyouragent/vault/bitwarden.json`, and start the vault again.

The vault fills a value only when all of these hold:

- the page's address has the same scheme, host and port as an address saved with the item (stricter than Bitwarden's default, so a sister subdomain or plain http does not qualify; "regular expression" and "never" match rules are not used);
- the field is in the page itself, not in a frame;
- the field is the right kind: a password only into a password field, a code only into a one-time-code field, a username only into a text or email field. So a password cannot be typed into a comment box and posted.

Every fill appears in the owner's activity as `secret_filled`, with the item name and field, never the value. `read_page` never returns field values. Submitting the form still follows the approval rules above.

Details and known limits: [vault guide](https://github.com/kjames2001/authyouragent/blob/main/vault/README.md).

### Your own code

If your agent drives its own Playwright browser, call the helper while the stuck page is open. The agent then holds the session the owner signs in to, so prefer the vault where you can. It returns when the owner is finished. While it waits, your agent must not act on the page.

Python (Playwright, Chromium):

```python
from authyouragent.agent import AgentClient
from authyouragent.takeover import takeover, login_finished

result = await takeover(agent, page, "Please sign in to jobs.example.com",
                        check=login_finished)
if result == "done":
    ...  # carry on with the task
```

JavaScript (Playwright, Chromium; also `npm i ws`):

```js
import { takeover, loginFinished } from "authyouragent/takeover";

const result = await takeover(agent, page, "Please sign in to jobs.example.com",
                              { check: loginFinished });
```

The result is one of:

- `done`: the owner finished. Read the page again before continuing.
- `incomplete`: the owner handed back, the check still failed, and a second request also ended unfinished.
- `cancelled`: the owner declined. Stop and tell them.
- `expired`: nobody took over within 10 minutes.
- `agent_left`: the connection to the agent dropped.

## Automatic handback

With a `check`, the helper watches the page while the owner is in control. Once the check has passed for 3 seconds in a row, the browser is handed back without the owner pressing Done. The 3 seconds catch a 2FA page that appears a moment after the password. The watch starts only if the check failed when the takeover began, so a page that was never blocked is not handed back early.

`login_finished` treats the page as not finished while it shows any of these:

- a password field;
- a one-time-code field: `autocomplete="one-time-code"`, a field named or labelled code, OTP, verification, 2FA, MFA, PIN or token, or a short number-only field;
- a row of four or more one-character boxes;
- sign-in approval text such as "Approve sign in request", "Check your phone", "2-Step Verification" or "Verify it's you".

Postcode, promo, coupon and search fields are not treated as codes. It reads form fields and page text only, with no screenshots, so agents without a vision model can use it. If a site's 2FA page is not recognised, the owner can still press Done, and your own `check` can cover it. You can pass your own check, for example one that looks for the account name on the page:

```python
async def signed_in(page):
    return await page.get_by_text("Your orders").count() > 0

result = await takeover(agent, page, "Please sign in", check=signed_in)
```

If the owner presses Done but the check still fails, the helper asks them once more ("That doesn't look finished yet…"). Change this with `retries`.

## What it needs from the agent

With the vault: Docker on the machine that runs it. With the SDK helper: a Chromium browser (Chrome, Chromium, Edge or a headless shell) that your code controls with Playwright. Hosted browser services often keep that connection to themselves; use their own live view there.

## Privacy and limits

- Only the agent's owner can open the live view. The agent authenticates with its own key, as for every other request.
- Keystrokes pass through Auth Your Agent to the agent's browser and are not stored. The helper never reads the value of a password field.
- With the SDK helper, the page is shown at phone size (412 x 760) while the owner is in control and restored afterwards; the vault is phone-sized from the start. Pass `phone_size=None` (Python) or `phoneSize: null` (JS) to keep your own size.
- One open takeover per agent. A takeover lasts at most 10 minutes.
- Each step appears in the owner's Activity: asked, taken over, handed back, declined, timed out.

## Ending the owner's session

When the owner signs in during a take over, the site sets cookies in the agent's browser. Wiping them only removes the browser's copy: the session stays valid on the site until it expires. So sessions are ended in this order: **sign out first, wipe second**.

### Vault (MCP)

Call `end_session`. The vault signs out of every site used (known sign-out routes, routes that worked before, the site's OpenID Connect sign-out endpoint, or a sign-out control on its pages), confirms it by the session cookie being cleared, then destroys the profile. Sites it could not sign out of are listed as "wiped locally, not signed out" so the owner can end them from the site's own device list.

### SDK helper

Pass `clear_session=True` to clear cookies, localStorage and sessionStorage after the owner finishes, or leave it `False` (default) to keep the session for the task. Clearing does not sign out; sign out through the site first when the task is done, then clear:

```python
result = await takeover(agent, page, "Please sign in to example.com",
                        check=login_finished)
# ... work on the logged-in page, then sign out through the site ...
from authyouragent.takeover import _clear_session
await _clear_session(page)
agent.report_status("session_cleared", site="example.com")
```

JavaScript: `clearSession: true` or `false` (default).

The owner's typed credentials are never stored or read. If the owner cancels or the take over times out, nothing is cleared (no sign-in happened). If the owner presses Done but the page still looks blocked (`incomplete`), the session is cleared as a safety measure.

## HTTP API

If you are not using an SDK:

1. `POST /api/v1/takeover` with `{"agent_id", "agent_jwt", "url", "reason"}` returns `{"takeover_id", "agent_token", "expires_in"}`.
2. Open a WebSocket to `/api/v1/takeover/{takeover_id}/agent` with the header `Authorization: Bearer <agent_token>`. A token in the URL is refused.
3. Send `{"t":"frame","data":<base64 JPEG>,"w":..,"h":..}` for each screen frame (for example from CDP `Page.startScreencast`), `{"t":"url","url":..}` after navigation, and `{"t":"focus","field":{"x","y","w","h","kind","fs","value"}}` (or `"field": null`) after each click. Send `{"t":"done"}` when your own check sees the job finished.
4. You receive `live`, `click` (`x`, `y` in page pixels), `set` (`value`: replace the focused field's text), `text`, `key`, `scroll` (`dy`) and a final `done`, `cancelled` or `expired`.

## Status reporting

The MCP server reports the agent's status to the Auth Your Agent server throughout:

- `takeover_started` -- when the agent requests a takeover
- `takeover_done` / `takeover_cancelled` / `takeover_expired` -- when the takeover ends
- `session_cleared` -- per site, when a session ends; the detail says whether sign-out was confirmed
- `session_not_signed_out` -- per site, when a vault stopped before it could sign out, with the page where the owner can end that session

These appear in the owner's activity log and dashboard.

## Agent-initiated approval

The `request_approval` tool sends a push notification to the owner's phone with the site and action. The owner approves or denies. This does NOT require the site to have adopted Auth Your Agent -- it works for any site, using the `POST /api/v1/agent-approval` endpoint.

Outside MCP, the same request is `agent.request_approval(site, action)` in the Python SDK, or `authyouragent approve <site> <action>` in a shell script or CI step, which exits 0 only when approved: `authyouragent approve npmjs.com publish && npm publish`. See [Approval for anything else](/docs/developers/agent-sdk#approval-for-anything-else).

## Agent revocation

The owner can revoke an agent at any time from the Auth Your Agent app. The `check_agent_status` tool detects this and tells the agent to stop, and the vault ends the session by itself. Every server call (takeover, approval, status report) also validates the agent's JWT, so a revoked agent cannot make further requests.
