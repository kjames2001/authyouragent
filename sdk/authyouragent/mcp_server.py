"""Auth Your Agent, as an MCP server.

A thin client of the Auth Your Agent browser vault. The browser runs inside the
vault container; its debug port never leaves the container, so this server and
the agent that uses it cannot read the owner's cookies. The agent drives the
browser only through these tools, and the owner can take over from their phone.

    {"mcpServers": {"authyouragent": {
        "command": "authyouragent-mcp",
        "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/agent.pem",
                "AYA_VAULT_URL": "http://127.0.0.1:7801",
                "AYA_VAULT_TOKEN_FILE": "/path/vault.token"}}}}

Environment:
  AYA_AGENT_ID          agent id from the Auth Your Agent app (required)
  AYA_KEY_FILE          the agent's private key, PEM (required)
  AYA_CLOUD             default https://authyouragent.com
  AYA_VAULT_URL         the vault broker (default http://127.0.0.1:7801)
  AYA_VAULT_TOKEN_FILE  file holding the vault's bearer token (or AYA_VAULT_TOKEN)
  AYA_VAULT_AUTOSTART   default 1: start the local vault (Docker) on first use if
                        it is not running. Set 0 to manage it with `authyouragent vault`.

Tools: navigate, read_page, click, type_text, press_key, select_option, scroll,
       go_back, wait_for, screenshot, check_login_wall, list_secrets, fill_secret,
       request_takeover, wait_for_takeover, request_approval, end_session,
       check_agent_status, report_site.

The vault ends the session by itself (real sign-out, then the browser profile is
destroyed) if this server stops sending heartbeats or the owner revokes the agent.
"""
import asyncio
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

try:                        # mcp 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP, Context
    from mcp.server.mcpserver import Image
except ImportError:         # mcp 1.x
    from mcp.server.fastmcp import FastMCP, Context, Image

from .agent import AgentClient

DEFAULT_CLOUD = "https://authyouragent.com"
WAIT_DEFAULT = 240          # stay under common MCP client call timeouts (300s)
WAIT_MAX = 290
HEARTBEAT_S = 20
AUTOSTART_WAIT = 120        # the first start downloads the image (~500 MB)

mcp = FastMCP("authyouragent")
_agent = None
_vault = None
_hb = None
_starting = None            # the background task starting the vault, if any


def _log(*a):
    print("[authyouragent-mcp]", *a, file=sys.stderr, flush=True)


def _get_agent():
    global _agent
    if _agent is None:
        aid, kf = os.environ.get("AYA_AGENT_ID"), os.environ.get("AYA_KEY_FILE")
        if not aid or not kf:
            raise RuntimeError("set AYA_AGENT_ID and AYA_KEY_FILE in this MCP server's env")
        _agent = AgentClient(base_url=os.environ.get("AYA_CLOUD", DEFAULT_CLOUD),
                             agent_id=aid, privkey_pem=open(os.path.expanduser(kf)).read(),
                             verify=not os.environ.get("AYA_INSECURE"))
    return _agent


class NoVaultToken(RuntimeError):
    pass


def _autostart_ok():
    """Start the vault ourselves only when it is the local one `vault up` would
    create: default address, and the token file it writes (or none set)."""
    if os.environ.get("AYA_VAULT_AUTOSTART", "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    if os.environ.get("AYA_VAULT_TOKEN"):
        return False
    u = urlparse(os.environ.get("AYA_VAULT_URL", "http://127.0.0.1:7801"))
    if u.hostname not in ("127.0.0.1", "localhost") or u.port != 7801:
        return False
    from . import vault_cli
    tf = os.environ.get("AYA_VAULT_TOKEN_FILE")
    return not tf or Path(tf).expanduser().resolve() == (vault_cli.HOME / "token").resolve()


async def _ensure_vault():
    """Start the local vault in the background and wait for it, up to
    AUTOSTART_WAIT. If it is still starting, say so; the next call waits again."""
    global _starting, _vault
    from . import vault_cli
    if _starting is None or (_starting.done() and (_starting.cancelled() or _starting.exception())):
        _log("the browser vault is not running: starting it")
        _starting = asyncio.create_task(asyncio.to_thread(
            vault_cli.start, os.environ.get("AYA_AGENT_ID"), os.environ.get("AYA_KEY_FILE"),
            cloud=os.environ.get("AYA_CLOUD", DEFAULT_CLOUD), log=_log))
    done, _ = await asyncio.wait({_starting}, timeout=AUTOSTART_WAIT)
    if not done:
        raise RuntimeError("the browser vault is starting (the first start downloads about 500 MB). "
                           "Call the tool again in a minute.")
    if _starting.exception():
        raise RuntimeError(f"could not start the browser vault: {_starting.exception()}")
    if _vault is not None:          # the token may be new: connect again
        await _vault.aclose()
        _vault = None


def _vault_client():
    global _vault
    if _vault is None:
        token = os.environ.get("AYA_VAULT_TOKEN", "")
        tf = os.environ.get("AYA_VAULT_TOKEN_FILE")
        if tf:
            token = open(os.path.expanduser(tf)).read().strip()
        if not token:
            default = os.path.expanduser("~/.authyouragent/vault/token")
            if os.path.exists(default):
                token = open(default).read().strip()
        if not token:
            raise NoVaultToken("no vault token: run `authyouragent vault up`, or set AYA_VAULT_TOKEN_FILE")
        _vault = httpx.AsyncClient(base_url=os.environ.get("AYA_VAULT_URL", "http://127.0.0.1:7801"),
                                   headers={"Authorization": f"Bearer {token}"},
                                   timeout=httpx.Timeout(60, read=WAIT_MAX + 30))
    return _vault


async def _heartbeat():
    """Keep the vault's lease alive while this server runs. If this process
    dies the heartbeats stop and the vault ends the session by itself."""
    while True:
        try:
            await _vault_client().post("/ping")
        except Exception:
            pass
        await asyncio.sleep(HEARTBEAT_S)


async def _call(method, path, **kw):
    global _hb
    if _hb is None or _hb.done():
        _hb = asyncio.create_task(_heartbeat())
    if _starting is not None and not _starting.done():
        await _ensure_vault()       # a start is under way: wait for it, never race it
    for attempt in (1, 2):
        try:
            r = await _vault_client().request(method, path, **kw)
            break
        except (httpx.ConnectError, NoVaultToken) as e:
            if attempt == 2 or not _autostart_ok():
                if isinstance(e, NoVaultToken):
                    raise
                raise RuntimeError("cannot reach the browser vault (not running). "
                                   "Start it with `authyouragent vault up`.")
            await _ensure_vault()
        except httpx.HTTPError as e:
            raise RuntimeError(f"cannot reach the browser vault ({type(e).__name__}); is it running?")
    data = r.json()
    if r.status_code == 409:
        raise RuntimeError(data.get("detail", "busy"))
    if r.status_code == 504 and data.get("error") == "result_unknown":
        raise RuntimeError("result unknown: " + data.get("detail", ""))
    if r.status_code >= 400:
        raise RuntimeError(f"vault error {r.status_code}: {data.get('detail') or data.get('error')}")
    return data


def _where(d):
    return f"{d['url']} ({d['title']})" if d.get("title") else d.get("url", "")


def _err(e):
    return f"error: {e}"


def _target(ref, selector):
    if ref:
        return {"ref": ref}
    if selector:
        return {"selector": selector}
    raise RuntimeError("give ref (a number from read_page) or selector")


def _what(ref, selector):
    return f"[{ref}]" if ref else selector


def _elements(d):
    lines = []
    for e in d.get("elements", []):
        bits = [f"[{e['ref']}] {e['kind']}"]
        if e.get("label"):
            bits.append(f'"{e["label"]}"')
        if e.get("name"):
            bits.append(f"name={e['name']}")
        if "checked" in e:
            bits.append("checked" if e["checked"] else "unchecked")
        if e.get("value"):
            bits.append(f'value="{e["value"]}"')
        if e.get("placeholder"):
            bits.append(f'placeholder="{e["placeholder"]}"')
        if e.get("options"):
            more = f" +{e['more_options']} more" if e.get("more_options") else ""
            bits.append("options: " + " | ".join(e["options"]) + more)
        if e.get("href"):
            bits.append(f"-> {e['href']}")
        if e.get("where"):
            bits.append(f"({e['where']})")
        lines.append(" ".join(bits))
    if not lines:
        return ""
    sc = d.get("scroll") or {}
    tail = ""
    if sc and sc.get("height", 0) > sc.get("y", 0) + sc.get("view", 0) + 2:
        tail = "\n(more of the page is below: scroll to see it)"
    return "\n\nYou can act on (use the number as ref):\n" + "\n".join(lines) + tail


# ─── Browser tools ────────────────────────────────────────────────────────

@mcp.tool()
async def navigate(url: str) -> str:
    """Open a URL in the vault's browser and wait for the page to load. Returns the
    final URL and title, after any redirects (a redirect to a sign-in page means
    you need check_login_wall, then request_takeover). Only public websites open:
    local, private-network and internal addresses are refused with an error.
    The page keeps any session the owner signed in to during a take over.
    url: the full URL, e.g. "https://example.com/account"."""
    try:
        return f"page: {_where(await _call('POST', '/navigate', json={'url': url}))}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def click(ref: int = 0, selector: str = "") -> str:
    """Click an element on the current page and return the page's URL and title
    afterwards. If the click would commit something (it submits a form, or the
    button says create, send, save, delete, pay and the like), the vault first asks
    the owner to approve it on their phone and waits up to about five minutes; a
    denial returns an error and nothing is clicked. Sign-in and search forms are
    not interrupted.
    ref: the element's number from read_page (preferred).
    selector: or a CSS / Playwright selector, e.g. "button[type=submit]" or "text=Add Server"."""
    try:
        d = await _call('POST', '/click', json=_target(ref, selector))
        return f"clicked: {_what(ref, selector)}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def type_text(text: str, ref: int = 0, selector: str = "", submit: bool = False) -> str:
    """Type into a form field (replaces its value). Never use this for the owner's
    passwords or codes: use fill_secret if the owner saved the sign-in, otherwise
    ask for a take over.
    text: what to type.
    ref: the field's number from read_page (preferred).
    selector: or a CSS selector, e.g. "input[name=url]".
    submit: press Enter afterwards (asks the owner first if that submits a form)."""
    try:
        d = await _call('POST', '/type', json={**_target(ref, selector), 'text': text, 'submit': submit})
        return f"typed into: {_what(ref, selector)}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def press_key(key: str, ref: int = 0, selector: str = "") -> str:
    """Press a key in the page: Enter, Space, Tab, Shift+Tab, Escape, Backspace,
    Delete, ArrowUp/Down/Left/Right, PageUp, PageDown, Home, End. Escape closes
    pop-ups; arrows move through menus and lists. Enter or Space on something that
    submits or commits follows the same approval rules as a click.
    ref / selector: focus this element first (optional; otherwise the key goes to
    whatever has focus)."""
    try:
        body = {"key": key}
        if ref or selector:
            body.update(_target(ref, selector))
        d = await _call('POST', '/press', json=body)
        return f"pressed: {key}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def select_option(option: str, ref: int = 0, selector: str = "") -> str:
    """Choose an entry in a dropdown (<select>). read_page lists each dropdown's
    options. If choosing makes the page send data to the site, the owner is asked first.
    option: the visible text of the choice, e.g. "United Kingdom".
    ref: the dropdown's number from read_page (preferred), or selector."""
    try:
        d = await _call('POST', '/select', json={**_target(ref, selector), 'option': option})
        return f"chose: {option}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def scroll(direction: str = "down", ref: int = 0) -> str:
    """Scroll the page, to read further or to load more (endless lists).
    direction: down or up (most of a screen), top or bottom.
    ref: or bring that element from read_page into view.
    Call read_page afterwards: element numbers are renumbered on every read."""
    try:
        d = await _call('POST', '/scroll', json={"ref": ref} if ref else {"direction": direction})
        sc = d.get("scroll") or {}
        end = " (end of page)" if d.get("at_end") else ""
        return f"scrolled to {sc.get('y', '?')} of {sc.get('height', '?')}px{end}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def go_back() -> str:
    """Go back to the previous page, like the browser's Back button."""
    try:
        d = await _call('POST', '/back', json={})
        return f"page: {_where(d)}" if d.get("moved") else f"no previous page\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def wait_for(text: str = "", gone: str = "", seconds: float = 10) -> str:
    """Wait for the page to change, instead of guessing with sleeps.
    text: wait until this text is visible (e.g. "Order placed").
    gone: or wait until this text disappears (e.g. "Loading").
    Neither: wait until the page stops loading.
    seconds: at most this long, 1 to 30."""
    try:
        d = await _call('POST', '/wait', json={"text": text, "gone": gone, "seconds": seconds})
        return f"{'found' if d.get('found') else 'not found within the time'}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def screenshot(full_page: bool = False):
    """A picture of what the browser shows (JPEG), for when the text is not
    enough: charts, images, layouts, a page that reads oddly. read_page is
    cheaper; use this when you need to see.
    full_page: the whole page instead of the visible part."""
    import base64
    try:
        d = await _call('GET', '/screenshot', params={"full": "1" if full_page else "0"})
        return Image(data=base64.b64decode(d["jpeg_b64"]), format="jpeg")
    except Exception as e:
        return _err(e)


@mcp.tool()
async def list_secrets() -> str:
    """List the sign-ins the owner has made available to you from their password
    manager: each item's name, the sites it may be used on, and which fields it
    has (username, password, totp). Values are never shown to you."""
    try:
        items = (await _call('GET', '/secrets'))["items"]
    except Exception as e:
        return _err(e)
    if not items:
        return "no sign-ins are available (the owner has none in the shared folder)"
    return "\n".join(f"- {i['name']}: {', '.join(i['fields']) or 'no fields'}  "
                     f"(sites: {', '.join(i['sites']) or 'none'})" for i in items)


@mcp.tool()
async def fill_secret(name: str, field: str = "password", ref: int = 0, selector: str = "") -> str:
    """Fill a field from the owner's password manager. The vault types the value
    itself; you never see it. It only fills on a site saved with the item, and
    only the right kind of field: a password into a password field, a totp code
    into a one-time code field, a username into a text or email field. Then
    click the sign-in button as usual.
    name: the item name from list_secrets.
    field: username, password or totp.
    ref: the field's number from read_page (preferred), or selector, e.g. "input[type=password]"."""
    try:
        d = await _call('POST', '/fill_secret', json={**_target(ref, selector), 'name': name, 'field': field})
        return f"filled {field} of '{name}' into: {_what(ref, selector)}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def read_page(max_chars: int = 5000, max_elements: int = 80) -> str:
    """Read the current page: its URL, title, visible text in reading order, and a
    numbered list of what you can act on (links, buttons, fields, dropdowns with
    their options). Pass a number as `ref` to click, type_text, select_option,
    press_key or fill_secret. Numbers change on every read_page: read again after
    the page changes.
    max_chars: how much text to return, 200 to 20000 (default 5000).
    max_elements: how many elements to list, 0 to 300 (default 80)."""
    try:
        d = await _call('GET', '/read', params={'max_chars': max_chars, 'max_elements': max_elements})
        return f"url: {d['url']}\ntitle: {d['title']}\n\n{d['text']}{_elements(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def check_login_wall() -> str:
    """Check whether the page is stuck at a sign-in, one-time code (2FA) or sign-in
    approval step. Reads form fields and page text only."""
    try:
        d = await _call('GET', '/login_wall')
    except Exception as e:
        return _err(e)
    if d["blocked"]:
        return (f"blocked: yes\npage: {_where(d)}\nThe page asks for a password, a one-time code "
                f"or a sign-in approval. Call request_takeover so the owner can do it.")
    return f"blocked: no\npage: {_where(d)}"


NEXT = {
    "done": "The owner finished and handed the browser back. Continue your task on the "
            "signed-in page. When you are finished with the site, call end_session.",
    "cancelled": "The owner declined. Do not retry right away; tell them what you needed.",
    "expired": "Nobody took over within 10 minutes. Tell the owner, or try again later.",
    "agent_left": "The connection to the browser was lost during the take over. Try again.",
    "incomplete": "The owner pressed Done but the page still asks for a password, code or "
                  "approval. Ask them what happened before trying again.",
}


async def _wait(jid, wait_seconds, ctx):
    deadline = time.time() + max(5, min(int(wait_seconds or WAIT_DEFAULT), WAIT_MAX))
    while True:
        step = int(max(1, min(30, deadline - time.time())))
        d = await _call('GET', f'/takeover/{jid}', params={'wait': step})
        if d["state"] == "finished":
            return (f"result: {d['result']}\nafter: {d['after']}s\npage: {d['url']}\n"
                    f"{NEXT.get(d['result'], '')}")
        if d["state"] in ("error", "unknown"):
            return f"result: error\n{d.get('detail', 'no open take over with that id')}"
        if ctx is not None:
            try:
                await ctx.report_progress(d.get("after", 0), None)
            except Exception:
                pass
        if time.time() >= deadline:
            return (f"result: waiting\ntakeover_id: {jid}\nThe owner has not finished yet "
                    f"({d.get('after', 0)}s so far). Call wait_for_takeover with this takeover_id. "
                    f"Do not use the browser meanwhile.")


@mcp.tool()
async def request_takeover(reason: str, wait_seconds: int = WAIT_DEFAULT, ctx: Context = None) -> str:
    """Ask your owner to take over the browser from their phone when you are stuck at a
    login, 2FA code, CAPTCHA or anything only they can do. You are disconnected from the
    browser while they are in control, and you never see what they type.
    Returns result: done / cancelled / expired / incomplete, or result: waiting with a
    takeover_id for wait_for_takeover.
    reason: one short line shown to the owner, e.g. "Please sign in to example.com"."""
    try:
        d = await _call('POST', '/takeover', json={'reason': reason[:200]})
        _log("take over requested:", reason)
        return await _wait(d["takeover_id"], wait_seconds, ctx)
    except Exception as e:
        return _err(e)


@mcp.tool()
async def wait_for_takeover(takeover_id: str, wait_seconds: int = WAIT_DEFAULT,
                            ctx: Context = None) -> str:
    """Keep waiting for a take over that request_takeover returned as "waiting".
    Returns the same results as request_takeover: done (continue on the signed-in
    page), cancelled or expired (stop and tell your user), incomplete (the page
    still asks for sign-in), or waiting again with the same takeover_id.
    takeover_id: the id request_takeover returned, e.g. "tk_...".
    wait_seconds: how long to wait this time (default as request_takeover)."""
    try:
        return await _wait(takeover_id, wait_seconds, ctx)
    except Exception as e:
        return _err(e)


@mcp.tool()
async def end_session() -> str:
    """End the owner's session when you are finished with the web: the vault signs out
    of the sites used, then destroys the browser profile. Always call this when done.
    (The vault also does it by itself if you stop running or the owner revokes you.)"""
    try:
        d = await _call('POST', '/end_session', json={'why': 'agent finished'})
    except Exception as e:
        return _err(e)
    lines = [f"  {site}: {res}" for site, res in d.get("sign_out", {}).items()]
    return "ended\nBrowser profile destroyed." + ("\nSign-out:\n" + "\n".join(lines) if lines else "")


# ─── Owner / platform tools ───────────────────────────────────────────────

@mcp.tool()
async def request_approval(site: str, action: str, wait_seconds: int = 120,
                           ctx: Context = None) -> str:
    """Ask your owner to approve a sensitive action before you perform it.
    The owner receives a push notification on their phone showing the site and action.
    They approve or deny. You should not perform the action until this returns approved.
    Use this before deleting data, changing settings, making purchases, modifying
    permissions, or any action that could have irreversible consequences.
    site: the domain or URL of the site where the action will be performed, e.g. "github.com".
    action: a short label for the action, e.g. "delete repository", "change password",
            "purchase subscription".
    wait_seconds: how long to wait for the owner's response (default 120, max 290).
    Returns: "approved" or "denied" or "expired" (owner did not respond in time)."""
    agent = _get_agent()
    action_norm = re.sub(r"[^a-z0-9_ :-]", "", action.lower()).strip().replace(" ", "_")[:64] or "action"
    site_norm = re.sub(r"^https?://", "", site).split("/")[0].lower()[:200]

    try:
        r = await asyncio.to_thread(
            agent.client.post,
            f"{agent.base}/api/v1/agent-approval",
            json={"agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
                  "site": site_norm, "action": action_norm},
            timeout=15)
        if r.status_code != 200:
            return f"error: server returned {r.status_code}: {r.text[:200]}"
        data = r.json()
        txn_id = data.get("txn_id")
        _log("approval requested:", site_norm, action_norm, "txn:", txn_id)
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"

    deadline = time.time() + min(wait_seconds, WAIT_MAX)
    while time.time() < deadline:
        await asyncio.sleep(3)
        try:
            r = await asyncio.to_thread(
                agent.client.get,
                f"{agent.base}/api/v1/authz-requests/{txn_id}",
                timeout=10)
            if r.status_code == 200:
                status = r.json().get("status")
                if status in ("approved", "denied", "expired", "cancelled"):
                    _log("approval result:", status)
                    if status == "approved":
                        return (f"approved\nThe owner approved the action '{action_norm}' "
                                f"on {site_norm}. You may proceed.")
                    elif status == "denied":
                        return (f"denied\nThe owner denied the action '{action_norm}' "
                                f"on {site_norm}. Do not proceed.")
                    elif status == "expired":
                        return (f"expired\nThe owner did not respond in time for "
                                f"'{action_norm}' on {site_norm}.")
                    else:
                        return "cancelled\nThe approval was cancelled."
        except Exception:
            pass
        if ctx is not None:
            try:
                await ctx.report_progress(time.time() - (deadline - min(wait_seconds, WAIT_MAX)),
                                          None)
            except Exception:
                pass

    return (f"expired\nThe owner did not respond in time for '{action_norm}' "
            f"on {site_norm}.")


@mcp.tool()
async def submit_plan(title: str, start: str, end: str, steps: list[dict]) -> str:
    """Ask your owner, once and in advance, to pre-approve the actions of a
    task that will run later while they may be away (a scheduled job).
    Call it when the job is set up, not when it runs. The owner gets one card
    and approves all steps, some, or none. During the window, an action that
    matches a pre-approved step exactly goes through without a card; any
    other action asks as usual. If the owner does not answer a step's card
    in time, only that step and the steps chained to it ("after") are
    skipped; carry on with the others.
    title: what the task is, e.g. "Nightly Reddit posts" (up to 80 characters).
    start, end: the window, ISO 8601 with offset ("2026-10-05T15:00:00+02:00")
      or Unix seconds; 1 minute to 24 hours long.
    steps: up to 20, in order. Each step:
      {"id": "s1", "url": "https://www.reddit.com/r/x/submit",
       "button": "Post",                  # the button's words exactly
       "texts": ["the title", "the body"], # exact text it sends (required for posts/replies/messages)
       "path": "/r/x/submit",             # optional: exact path, or a prefix ending in *
       "after": ["s0"],                   # optional: steps that must be done first
       "uses": 1}                         # optional: times it may run, 1-5
    Payments and security changes are listed for the owner but never
    pre-approved: they always ask at the time.
    Returns the plan id and status; check it later with plan_status."""
    agent = _get_agent()

    def ts(v):
        v = str(v).strip()
        if re.fullmatch(r"\d{9,11}", v):
            return int(v)
        from datetime import datetime
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if d.tzinfo is None:
            raise ValueError("give the time with its offset, e.g. 2026-10-05T15:00:00+02:00")
        return int(d.timestamp())
    try:
        body = {"agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(), "title": title,
                "start_at": ts(start), "end_at": ts(end), "steps": steps}
        r = await asyncio.to_thread(agent.client.post, f"{agent.base}/api/v1/plans", json=body, timeout=15)
    except Exception as e:
        return f"error: {e}"
    if r.status_code != 200:
        try:
            return f"error: {r.json().get('detail')}"
        except Exception:
            return f"error: server returned {r.status_code}"
    j = r.json()
    never = j.get("never_pre_approved") or []
    return (f"submitted\nplan_id: {j['plan_id']}\nThe owner has a card to pre-approve it; they may answer "
            "until the window opens. If they do not, every step asks at the time and the run still goes ahead."
            + (f"\nAlways asks at the time (payment or security): {', '.join(never)}" if never else ""))


@mcp.tool()
async def plan_status(plan_id: str) -> str:
    """The state of a plan you submitted: for each step, whether it is
    pre-approved or asks at the time, and what happened (waiting, asking,
    running, done, skipped, denied, failed, unknown) with the reason."""
    agent = _get_agent()
    try:
        r = await asyncio.to_thread(agent.client.post, f"{agent.base}/api/v1/plans/{plan_id}/status", timeout=15,
                                    json={"agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt()})
    except Exception as e:
        return f"error: {e}"
    if r.status_code != 200:
        return f"error: server returned {r.status_code}"
    p = r.json()
    lines = [f"{p['title']}: {p['status']} (card: {p['card']})"]
    for i, s in enumerate(p["steps"], 1):
        how = "pre-approved" if s["pre_approved"] else "asks at the time"
        dep = f", after {', '.join(s['after'])}" if s["after"] else ""
        lines.append(f"{i}. {s['id']} '{s['button']}' on {s['host']}: {s['state']}"
                     + (f" ({s['reason']})" if s.get("reason") else "") + f"; {how}{dep}; used {s['used']}/{s['uses']}")
    return "\n".join(lines)


@mcp.tool()
async def notify_owner(text: str, title: str = "") -> str:
    """Send your owner a one-way note on their phone. Nothing to approve.
    Use it when the owner asked to hear back ("message me when you're done"),
    when you finish a long task, or when you are stuck and stopping.
    Say what happened, plainly, including anything that failed or that you
    could not check. Do not use it to ask permission: use request_approval.
    text: up to 600 characters. title: optional, defaults to your agent name.
    Also: when a browser session ends, the vault sends the owner its own
    summary (sites, approvals, sign-outs) whether or not you call this.
    Returns: sent / recorded (no device has notifications on) / error."""
    agent = _get_agent()
    try:
        sent = await asyncio.to_thread(agent.notify, text, title)
    except Exception as e:
        return f"error: {e}"
    return ("sent\nThe note is on the owner's phone." if sent else
            "recorded\nThe owner has no device with notifications on; the note is in their Activity log.")


@mcp.tool()
async def check_agent_status() -> str:
    """Check whether your agent is still authorized by the owner. The owner can revoke
    your access at any time from their phone. Call this periodically (e.g. before
    starting a new task) to verify you are still active.
    Returns: active / revoked / error."""
    agent = _get_agent()
    try:
        r = await asyncio.to_thread(
            agent.client.get,
            f"{agent.base}/api/v1/agent-status",
            headers={"X-Agent-JWT": agent._agent_jwt()},
            params={"agent_id": agent.agent_id},
            timeout=10)
        if r.status_code == 200:
            data = r.json()
            status = data.get("status", "active")
            if status == "revoked":
                return ("revoked\nThe owner has revoked your access. Stop all work "
                        "immediately and inform the owner.")
            revoked_sites = data.get("revoked_sites", [])
            return (f"active\nYou are authorized. Agent: {data.get('agent_name','?')}"
                    + (f"\nRevoked sites: {', '.join(revoked_sites)}" if revoked_sites else ""))
        elif r.status_code == 403:
            return "revoked\nThe owner has revoked your access. Stop all work immediately."
        elif r.status_code == 401:
            return "error: authentication failed (invalid agent JWT)"
        return f"error: server returned {r.status_code}"
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"


@mcp.tool()
async def report_site(site: str, kind: str, detail: str = "", url: str = "") -> str:
    """Report a site where take over did not work correctly, so the team can improve it.
    Call this whenever check_login_wall misses a login, takeover fails to complete,
    the handback does not trigger, or anything else goes wrong on a real site.
    site: the domain or URL, e.g. "reddit.com".
    kind: one of: shadow_dom, bot_detection, input_not_detected, takeover_failed,
          handback_failed, session_not_cleared, oauth_blocked, other.
    detail: one short line describing what happened (optional).
    url: the full page URL if known (optional)."""
    kinds = ("shadow_dom", "bot_detection", "input_not_detected",
             "takeover_failed", "handback_failed", "session_not_cleared", "oauth_blocked", "other")
    if kind not in kinds:
        return f"error: kind must be one of {', '.join(kinds)}"
    agent = _get_agent()
    try:
        r = await asyncio.to_thread(
            agent.client.post,
            f"{agent.base}/api/v1/takeover/report",
            json={"agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
                  "site": site[:200], "kind": kind, "detail": detail[:280],
                  "url": url[:500]})
        if r.status_code == 200:
            _log("site reported:", site, kind)
            return f"reported: {site} ({kind})\nThank you. The team will look into it."
        return f"error: server returned {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="authyouragent-mcp",
                                 description="Auth Your Agent MCP server (browser vault client)")
    ap.add_argument("--transport", choices=("stdio",), default="stdio")
    ap.parse_args()
    mcp.run("stdio")


if __name__ == "__main__":
    main()
