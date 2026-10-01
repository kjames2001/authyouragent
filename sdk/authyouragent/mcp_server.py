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

Tools: navigate, click, type_text, read_page, check_login_wall, list_secrets,
       fill_secret, request_takeover, wait_for_takeover, request_approval,
       end_session, check_agent_status, report_site.

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
except ImportError:         # mcp 1.x
    from mcp.server.fastmcp import FastMCP, Context

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
    if r.status_code >= 400:
        raise RuntimeError(f"vault error {r.status_code}: {data.get('detail') or data.get('error')}")
    return data


def _where(d):
    return f"{d['url']} ({d['title']})" if d.get("title") else d.get("url", "")


def _err(e):
    return f"error: {e}"


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
async def click(selector: str) -> str:
    """Click an element on the current page and return the page's URL and title
    afterwards. If the click would commit something (it submits a form, or the
    button says create, send, save, delete, pay and the like), the vault first asks
    the owner to approve it on their phone and waits up to about five minutes; a
    denial returns an error and nothing is clicked. Sign-in and search forms are
    not interrupted.
    selector: a CSS or Playwright selector, e.g. "button[type=submit]" or "text=Add Server"."""
    try:
        return f"clicked: {selector}\npage: {_where(await _call('POST', '/click', json={'selector': selector}))}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def type_text(selector: str, text: str, submit: bool = False) -> str:
    """Type into a form field (replaces its value). Never use this for the owner's
    passwords or codes: use fill_secret if the owner saved the sign-in, otherwise
    ask for a take over.
    selector: the field, e.g. "input[name=url]".
    text: what to type.
    submit: press Enter afterwards."""
    try:
        d = await _call('POST', '/type', json={'selector': selector, 'text': text, 'submit': submit})
        return f"typed into: {selector}\npage: {_where(d)}"
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
async def fill_secret(selector: str, name: str, field: str = "password") -> str:
    """Fill a field from the owner's password manager. The vault types the value
    itself; you never see it. It only fills on a site saved with the item, and
    only the right kind of field: a password into a password field, a totp code
    into a one-time code field, a username into a text or email field. Then
    click the sign-in button as usual.
    selector: the field, e.g. "input[type=password]".
    name: the item name from list_secrets.
    field: username, password or totp."""
    try:
        d = await _call('POST', '/fill_secret', json={'selector': selector, 'name': name, 'field': field})
        return f"filled {field} of '{name}' into: {selector}\npage: {_where(d)}"
    except Exception as e:
        return _err(e)


@mcp.tool()
async def read_page(max_chars: int = 5000) -> str:
    """Read the current page: its URL, title and visible text, in reading order.
    Use it after navigate or click to see what is on screen (no screenshot needed).
    Text in form fields and hidden elements is not included.
    max_chars: how much text to return, 200 to 20000 (default 5000)."""
    try:
        d = await _call('GET', '/read', params={'max_chars': max_chars})
        return f"url: {d['url']}\ntitle: {d['title']}\n\n{d['text']}"
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
