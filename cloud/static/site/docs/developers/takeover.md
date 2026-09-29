# Take over: when your agent is stuck

Your agent reaches a login page, a CAPTCHA or a 2FA prompt that it cannot or must not get past on its own. Instead of failing the task, it asks its owner to take over. The owner's phone gets a notification and a live view of the agent's browser. They tap and type on the page as if it were their own browser, press the site's own Sign in button, and the agent continues.

The site does not need to support Auth Your Agent. It sees an ordinary person signing in.

## What the owner sees

1. A notification: "Auth Your Agent: <agent name> needs you", with the reason your agent gave.
2. A live view of the agent's page, sized for a phone.
3. When they tap a field on the page, a real text box appears over it, so they type straight into the page. Password fields get a password box; code fields get the number keypad, and a row of one-digit boxes gets a single box across the row.
4. After they press the page's Sign in (or Submit) button, the view closes with **Done, handed back**. They can also press **Done** themselves at any time, or **Cancel**.

## Add it to your agent

### Any MCP agent: no code

If your agent supports MCP (Model Context Protocol) and drives a Chromium browser, add the Auth Your Agent MCP server. Install it once:

```sh
pip install "authyouragent[mcp]"
```

Then add it to your agent's MCP settings:

```json
{"mcpServers": {"authyouragent": {
  "command": "authyouragent-mcp",
  "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/to/agent-key.pem"}
}}}
```

`AYA_AGENT_ID` and the key come from adding the agent in the app (**Agents → Add an agent**). The server finds a Chromium on the same machine that was started with `--remote-debugging-port`, which covers most agent browsers. Otherwise set `AYA_CDP_URL` to the browser's debugging port or URL.

Your agent gets three tools:

- `check_login_wall`: is the page asking for a password, a code or a sign-in approval? Answers `blocked: yes` or `blocked: no`.
- `request_takeover(reason)`: asks the owner to take over. It returns `result: done` (or `cancelled`, `expired`, `incomplete`) with a line saying what to do next. If the owner takes longer than `wait_seconds` (default 240, below most MCP call time limits), it returns `result: waiting` with a `takeover_id`.
- `wait_for_takeover(takeover_id)`: keeps waiting after `result: waiting`.

The tools answer in plain text and read the page's fields and text, not screenshots, so the model driving your agent does not need vision.

### Your own code

Call the helper while the stuck page is open. It returns when the owner is finished. While it waits, your agent must not act on the page.

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

Take over needs the agent's browser to be Chromium (Chrome, Chromium, Edge or a headless shell) reachable over the Chrome DevTools Protocol from where the helper or MCP server runs. Hosted browser services often keep that connection to themselves; use their own live view there.

## Privacy and limits

- Only the agent's owner can open the live view. The agent authenticates with its own key, as for every other request.
- Keystrokes pass through Auth Your Agent to the agent's browser and are not stored. The helper never reads the value of a password field.
- The page is shown at phone size (412 x 760) while the owner is in control and restored afterwards. Pass `phone_size=None` (Python) or `phoneSize: null` (JS) to keep your own size.
- One open takeover per agent. A takeover lasts at most 10 minutes.
- Each step appears in the owner's Activity: asked, taken over, handed back, declined, timed out.

## Clearing the owner's session

When the owner signs in during a take over, the site sets cookies and session tokens in the agent's browser. Without clearing them, the agent could keep using the owner's login after the take over ends — potentially unlimited access.

Pass `clear_session=True` (Python) or `clearSession: true` (JavaScript) to clear cookies, localStorage and sessionStorage from the page's context after the owner finishes. The MCP server does this by default. The owner's typed credentials are never stored or read; only what the site itself saved in the browser is cleared.

```python
result = await takeover(agent, page, "Please sign in to example.com",
                        check=login_finished, clear_session=True)
```

If the owner cancels or the take over times out, nothing is cleared (no login happened). If the owner presses Done but the page still looks blocked (`incomplete`), the session is cleared as a safety measure.

## HTTP API

If you are not using an SDK:

1. `POST /api/v1/takeover` with `{"agent_id", "agent_jwt", "url", "reason"}` returns `{"takeover_id", "agent_token", "expires_in"}`.
2. Open a WebSocket to `/api/v1/takeover/{takeover_id}/agent` with the header `Authorization: Bearer <agent_token>`. A token in the URL is refused.
3. Send `{"t":"frame","data":<base64 JPEG>,"w":..,"h":..}` for each screen frame (for example from CDP `Page.startScreencast`), `{"t":"url","url":..}` after navigation, and `{"t":"focus","field":{"x","y","w","h","kind","fs","value"}}` (or `"field": null`) after each click. Send `{"t":"done"}` when your own check sees the job finished.
4. You receive `live`, `click` (`x`, `y` in page pixels), `set` (`value`: replace the focused field's text), `text`, `key`, `scroll` (`dy`) and a final `done`, `cancelled` or `expired`.
