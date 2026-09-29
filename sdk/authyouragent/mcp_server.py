"""Auth Your Agent Take over, as an MCP server.

Any MCP-capable agent that drives a Chromium browser can ask its owner to
take over that browser from their phone (sign in, 2FA, CAPTCHA), then carry
on. No code changes in the agent: add this server to its MCP config.

    {"mcpServers": {"authyouragent": {
        "command": "authyouragent-mcp",
        "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/agent.pem",
                "AYA_CDP_URL": "http://127.0.0.1:9222"}}}}

Environment:
  AYA_AGENT_ID   agent id from the Auth Your Agent app (required)
  AYA_KEY_FILE   the agent's private key, PEM (required)
  AYA_CLOUD      default https://authyouragent.com
  AYA_CDP_URL    the agent's browser: CDP port, http:// or ws:// URL, or
                 "auto" (default) to find a local Chromium started with
                 --remote-debugging-port. The agent can also pass cdp_url.

Tools: check_login_wall, request_takeover, wait_for_takeover, request_approval,
       clear_session, check_agent_status, report_site.
Every check reads the page's form fields and text; no screenshots, so
agents without vision can use it. Requires `pip install "authyouragent[mcp]"`.
"""
import asyncio
import os
import sys
import time
import uuid

try:                        # mcp 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP, Context
except ImportError:         # mcp 1.x
    from mcp.server.fastmcp import FastMCP, Context

from .agent import AgentClient
from .takeover import BLOCKING_JS, takeover

DEFAULT_CLOUD = "https://authyouragent.com"
WAIT_DEFAULT = 240          # stay under common MCP client call timeouts (300s)
WAIT_MAX = 290

mcp = FastMCP("authyouragent")
_jobs = {}                  # local id -> {"task", "started", "url", "reason"}
_agent = None


def _log(*a):
    print("[authyouragent-mcp]", *a, file=sys.stderr, flush=True)


def _get_agent():
    global _agent
    if _agent is None:
        aid, kf = os.environ.get("AYA_AGENT_ID"), os.environ.get("AYA_KEY_FILE")
        if not aid or not kf:
            raise RuntimeError("set AYA_AGENT_ID and AYA_KEY_FILE in this MCP server's env")
        _agent = AgentClient(base_url=os.environ.get("AYA_CLOUD", DEFAULT_CLOUD),
                             agent_id=aid, privkey_pem=open(kf).read(),
                             verify=not os.environ.get("AYA_INSECURE"))
    return _agent


def _local_chromiums():
    """CDP URLs of local Chromium browsers started with --remote-debugging-port,
    newest first. Chromium writes the chosen port to DevToolsActivePort in its
    profile folder, which also covers port 0 (agent-browser, Puppeteer)."""
    found = []
    for pid in (d for d in os.listdir("/proc") if d.isdigit()) if os.path.isdir("/proc") else ():
        try:
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
        # Chromium rewrites its argv into one space-joined string, so split on spaces too
        # (a user-data-dir containing spaces is not supported by this lookup)
        args = [w for a in args for w in a.decode(errors="replace").split(" ") if w]
        if not any(a.startswith("--remote-debugging-port") for a in args) or \
                any(a.startswith("--type=") for a in args):
            continue
        port = next((a.split("=", 1)[1] for a in args if a.startswith("--remote-debugging-port=")), "0")
        udd = next((a.split("=", 1)[1] for a in args if a.startswith("--user-data-dir=")), "")
        f = os.path.join(udd, "DevToolsActivePort") if udd else ""
        if f and os.path.exists(f):
            lines = open(f).read().split()
            if lines:
                found.append((os.path.getmtime(f), f"http://127.0.0.1:{lines[0]}"))
        elif port != "0":
            found.append((0, f"http://127.0.0.1:{port}"))
    return [u for _, u in sorted(found, reverse=True)]


def _cdp_candidates(cdp_url):
    u = (cdp_url or os.environ.get("AYA_CDP_URL", "") or "auto").strip()
    if u.isdigit():
        return [f"http://127.0.0.1:{u}"]
    if u != "auto":
        return [u]
    c = _local_chromiums()
    if not c:
        raise RuntimeError("no browser found: pass cdp_url (the CDP port or URL of your "
                           "Chromium) or start it with --remote-debugging-port")
    return c


def _web_pages(browser):
    return [pg for ctx in browser.contexts for pg in ctx.pages
            if pg.url.startswith(("http://", "https://"))]


async def _page(p, cdp_url, page_url):
    """Connect over CDP and pick the agent's page: the tab matching page_url, else
    the newest web page. With several local browsers, the newest one that has a
    matching tab wins."""
    want = page_url.split("#")[0].split("?")[0] if page_url else ""
    fallback, errors = None, []
    for u in _cdp_candidates(cdp_url):
        try:
            browser = await p.chromium.connect_over_cdp(u, timeout=8000)
        except Exception as e:
            errors.append(f"{u}: {type(e).__name__}")
            continue
        pages = _web_pages(browser)
        hit = [pg for pg in pages if want and pg.url.split("#")[0].startswith(want)]
        if hit:
            return hit[-1]
        if pages and fallback is None:
            fallback = pages[-1]
        if not want and fallback is not None:
            return fallback
    if fallback is not None:
        return fallback
    raise RuntimeError("no open web page in the browser" + (f" ({'; '.join(errors)})" if errors else ""))


def _playwright():
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise RuntimeError('pip install "authyouragent[mcp]" (needs playwright)')
    return async_playwright()


async def _describe(page):
    try:
        title = await page.title()
    except Exception:
        title = ""
    return f"{page.url} ({title})" if title else page.url


NEXT = {
    "done": "The owner finished and handed the browser back. The owner's login session "
            "(cookies, localStorage) has been cleared so you cannot reuse it. Continue "
            "your task in the same browser; you are now past the step that needed them.",
    "cancelled": "The owner declined. Do not retry right away; tell them what you needed.",
    "expired": "Nobody took over within 10 minutes. Tell the owner, or try again later.",
    "agent_left": "The connection to the browser was lost during the take over. "
                  "Check the browser is still open, then try again.",
    "incomplete": "The owner pressed Done but the page still asks for a password, code or "
                  "approval. Ask them what happened before trying again.",
}


def _report(job_id, job, result):
    secs = int(time.time() - job["started"])
    return (f"result: {result}\nafter: {secs}s\npage: {job.get('final') or job['url']}\n"
            f"{NEXT.get(result, '')}")


async def _run(job, cdp_url, page_url, reason):
    agent = _get_agent()
    async with _playwright() as p:
        page = await _page(p, cdp_url, page_url)
        job["url"] = page.url

        # Report takeover started to server (for owner dashboard)
        agent.report_status("takeover_started", site=page.url.split("/")[2] if "/" in page.url else "",
                            detail=reason[:200])

        async def check(pg):
            try:
                return not await pg.evaluate(BLOCKING_JS)
            except Exception:
                return False
        result = await takeover(agent, page, reason,
                                verify=not os.environ.get("AYA_INSECURE"), check=check,
                                clear_session=False)
        job["final"] = await _describe(page)
        # Report takeover result to server
        agent.report_status(f"takeover_{result}", site=page.url.split("/")[2] if "/" in page.url else "")
        return result     # leaving the block only drops our CDP link; the browser stays open


async def _wait(job_id, wait_seconds, ctx):
    job = _jobs[job_id]
    deadline = time.time() + max(5, min(int(wait_seconds or WAIT_DEFAULT), WAIT_MAX))
    while time.time() < deadline:
        done, _ = await asyncio.wait({job["task"]}, timeout=min(10, deadline - time.time()))
        if done:
            try:
                result = job["task"].result()
            except Exception as e:
                _jobs.pop(job_id, None)
                return f"result: error\n{type(e).__name__}: {e}"
            _jobs.pop(job_id, None)
            return _report(job_id, job, result)
        if ctx is not None:   # keeps clients that reset their timeout on progress alive
            try:
                await ctx.report_progress(time.time() - job["started"], None)
            except Exception:
                pass
    return (f"result: waiting\ntakeover_id: {job_id}\nThe owner has not finished yet "
            f"({int(time.time() - job['started'])}s so far). Call wait_for_takeover with this "
            f"takeover_id to keep waiting. Do not touch the browser meanwhile.")


@mcp.tool()
async def check_login_wall(cdp_url: str = "", page_url: str = "") -> str:
    """Check whether the browser page is stuck at a sign-in, one-time code (2FA) or
    sign-in approval step. Reads form fields and page text only (no screenshot).
    cdp_url: your Chromium's CDP port or URL (optional if the server has a default).
    page_url: which tab, if several are open (optional)."""
    async with _playwright() as p:
        page = await _page(p, cdp_url, page_url)
        try:
            blocked = await page.evaluate(BLOCKING_JS)
        except Exception:
            blocked = False
        where = await _describe(page)
    if blocked:
        return (f"blocked: yes\npage: {where}\nThe page asks for a password, a one-time code "
                f"or a sign-in approval. Call request_takeover so the owner can do it.")
    return f"blocked: no\npage: {where}"


@mcp.tool()
async def request_takeover(reason: str, cdp_url: str = "", page_url: str = "",
                           wait_seconds: int = WAIT_DEFAULT, ctx: Context = None) -> str:
    """Ask your owner to take over your browser from their phone, when you are stuck at
    a login, 2FA code, CAPTCHA or anything only they can do. They see the live page,
    type straight into it, and hand it back; you never see their password.
    Returns when they finish (result: done / cancelled / expired / incomplete), or after
    wait_seconds with result: waiting and a takeover_id for wait_for_takeover.
    reason: one short line shown to the owner, e.g. "Please sign in to example.com".
    cdp_url: your Chromium's CDP port or URL (optional if the server has a default).
    page_url: which tab, if several are open (optional).
    After handback the owner's login session stays active so you can continue your task
    on the logged-in page. When you are done with the site, call clear_session to wipe
    cookies, localStorage and sessionStorage so you cannot reuse the owner's session."""
    active = [k for k, j in _jobs.items() if not j["task"].done()]
    if active:
        return (f"result: busy\ntakeover_id: {active[0]}\nA take over is already open. "
                f"Call wait_for_takeover with this takeover_id.")
    job_id = "tk_" + uuid.uuid4().hex[:10]
    job = {"started": time.time(), "url": page_url or "", "reason": reason}
    job["task"] = asyncio.create_task(_run(job, cdp_url, page_url, (reason or "")[:200]))
    _jobs[job_id] = job
    _log("take over requested:", reason)
    return await _wait(job_id, wait_seconds, ctx)


@mcp.tool()
async def wait_for_takeover(takeover_id: str, wait_seconds: int = WAIT_DEFAULT,
                            ctx: Context = None) -> str:
    """Keep waiting for a take over that request_takeover reported as still waiting."""
    if takeover_id not in _jobs:
        return "result: unknown\nNo open take over with that id (it may have finished already)."
    return await _wait(takeover_id, wait_seconds, ctx)


@mcp.tool()
async def report_site(site: str, kind: str, detail: str = "", url: str = "") -> str:
    """Report a site where take over did not work correctly, so the team can improve it.
    Call this whenever check_login_wall misses a login, takeover fails to complete,
    the handback does not trigger, or anything else goes wrong on a real site.
    site: the domain or URL, e.g. "reddit.com".
    kind: one of: shadow_dom, bot_detection, input_not_detected, takeover_failed,
          handback_failed, session_not_cleared, other.
    detail: one short line describing what happened (optional).
    url: the full page URL if known (optional)."""
    import httpx
    kinds = ("shadow_dom", "bot_detection", "input_not_detected",
             "takeover_failed", "handback_failed", "session_not_cleared", "other")
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
            "purchase subscription". Keep it under 64 chars, lowercase with underscores.
    wait_seconds: how long to wait for the owner's response (default 120, max 290).
    Returns: "approved" or "denied" or "expired" (owner did not respond in time)."""
    import httpx
    agent = _get_agent()
    # Normalize action
    import re
    action_norm = re.sub(r"[^a-z0-9_ :-]", "", action.lower()).strip().replace(" ", "_")[:64] or "action"
    site_norm = re.sub(r"^https?://", "", site).split("/")[0].lower()[:200]

    # Request approval from the server (agent-initiated, no site grant needed)
    try:
        r = await asyncio.to_thread(
            agent.client.post,
            f"{agent.base}/api/v1/agent-approval",
            json={"agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
                  "site": site_norm, "action": action_norm},
            timeout=15
        )
        if r.status_code != 200:
            return f"error: server returned {r.status_code}: {r.text[:200]}"
        data = r.json()
        txn_id = data.get("txn_id")
        expires_in = data.get("expires_in", 60)
        _log("approval requested:", site_norm, action_norm, "txn:", txn_id)
    except Exception as e:
        return f"error: {type(e).__name__}: {e}"

    # Poll for the owner's response
    deadline = time.time() + min(wait_seconds, WAIT_MAX)
    while time.time() < deadline:
        await asyncio.sleep(3)
        try:
            r = await asyncio.to_thread(
                agent.client.get,
                f"{agent.base}/api/v1/authz-requests/{txn_id}",
                timeout=10
            )
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
                        return f"cancelled\nThe approval was cancelled."
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
async def clear_session(cdp_url: str = "", page_url: str = "") -> str:
    """Clear the browser session (cookies, localStorage, sessionStorage) on the current
    page. Call this when you are done with a site after a takeover, so the owner's login
    session is wiped and you cannot reuse it. This is the cleanup step after
    request_takeover. You should not call this until your task on the site is complete.
    cdp_url: your Chromium's CDP port or URL (optional if the server has a default).
    page_url: which tab, if several are open (optional)."""
    from .takeover import _clear_session
    async with _playwright() as p:
        page = await _page(p, cdp_url, page_url)
        where = await _describe(page)
        await _clear_session(page)
    # Report to server so the user's dashboard shows the session was cleared
    agent = _get_agent()
    agent.report_status("session_cleared", site=where[:200])
    _log("session cleared on:", where)
    return f"cleared\nSession (cookies, localStorage, sessionStorage) cleared on {where}."


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


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="authyouragent-mcp", description="Auth Your Agent Take over MCP server")
    ap.add_argument("--transport", choices=("stdio",), default="stdio")
    ap.parse_args()
    mcp.run("stdio")


if __name__ == "__main__":
    main()
