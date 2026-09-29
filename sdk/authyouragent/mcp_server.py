"""Auth Your Agent Take over, as an MCP server.

Any MCP-capable agent can ask its owner to take over its browser from their
phone (sign in, 2FA, CAPTCHA), then carry on. The MCP server owns the browser
connection — the agent never gets raw CDP access, so it cannot steal session
cookies.

    {"mcpServers": {"authyouragent": {
        "command": "authyouragent-mcp",
        "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/agent.pem",
                "AYA_CDP_URL": "http://127.0.0.1:9222"}}}}

Environment:
  AYA_AGENT_ID   agent id from the Auth Your Agent app (required)
  AYA_KEY_FILE   the agent's private key, PEM (required)
  AYA_CLOUD      default https://authyouragent.com
  AYA_CDP_URL    a browser: CDP port, http:// or ws:// URL, or
                 "auto" (default) to find or start a local Chromium.

Tools: check_login_wall, request_takeover, wait_for_takeover, request_approval,
       clear_session, check_agent_status, report_site,
       navigate, click, type_text, read_page.

Browser tools (navigate, click, type_text, read_page) let the agent interact
with the page through the MCP server's owned connection. The agent never gets
direct CDP access, so it cannot read cookies or localStorage.
Requires `pip install "authyouragent[mcp]"` and `playwright install chromium`.
"""
import asyncio
import os
import re
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
_bw = None                  # BrowserManager singleton

# Content script that blocks cookie/localStorage reads after takeover.
# Injected via addInitScript so it runs before any page JS on every navigation.
_SESSION_GUARD_JS = """
(() => {
  const orig = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (orig) {
    Object.defineProperty(document, 'cookie', {
      get: () => '',
      set: orig.set,
      configurable: true
    });
  }
})();
"""


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
    newest first."""
    found = []
    for pid in (d for d in os.listdir("/proc") if d.isdigit()) if os.path.isdir("/proc") else ():
        try:
            args = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
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


_chromium_proc = None

def _ensure_chromium():
    """Start a headless Chromium with --remote-debugging-port if none is running.
    Returns the CDP URL, or None if it could not start."""
    global _chromium_proc
    if _chromium_proc and _chromium_proc.poll() is None:
        try:
            import urllib.request
            urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=3)
            return "http://127.0.0.1:9222"
        except Exception:
            _chromium_proc = None

    # Try playwright's bundled chromium first
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            exe = p.chromium.executable_path
        if exe and os.path.exists(exe):
            import subprocess as sp, tempfile
            udd = tempfile.mkdtemp(prefix="aya-chromium-")
            _chromium_proc = sp.Popen(
                [exe, "--headless=new", "--no-sandbox", "--disable-gpu",
                 "--remote-debugging-port=9222", "--remote-allow-origins=*",
                 "--window-size=1280,900", f"--user-data-dir={udd}"],
                stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            import time, urllib.request
            for _ in range(20):
                time.sleep(0.5)
                try:
                    urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=2)
                    _log("auto-started Chromium on :9222")
                    return "http://127.0.0.1:9222"
                except Exception:
                    continue
    except Exception as e:
        _log("could not auto-start Chromium via Playwright:", e)

    # Fallback: try system chromium
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        try:
            import subprocess as sp, tempfile, shutil
            exe = shutil.which(name)
            if not exe:
                continue
            udd = tempfile.mkdtemp(prefix="aya-chromium-")
            _chromium_proc = sp.Popen(
                [exe, "--headless=new", "--no-sandbox", "--disable-gpu",
                 "--remote-debugging-port=9222", "--remote-allow-origins=*",
                 "--window-size=1280,900", f"--user-data-dir={udd}"],
                stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            import time, urllib.request
            for _ in range(20):
                time.sleep(0.5)
                try:
                    urllib.request.urlopen("http://127.0.0.1:9222/json/version", timeout=2)
                    _log(f"auto-started {name} on :9222")
                    return "http://127.0.0.1:9222"
                except Exception:
                    continue
        except Exception:
            continue

    return None


def _cdp_candidates(cdp_url):
    u = (cdp_url or os.environ.get("AYA_CDP_URL", "") or "auto").strip()
    if u.isdigit():
        return [f"http://127.0.0.1:{u}"]
    if u != "auto":
        return [u]
    c = _local_chromiums()
    if c:
        return c
    started = _ensure_chromium()
    if started:
        return [started]
    raise RuntimeError("no browser found: pass cdp_url (the CDP port or URL of your "
                       "Chromium) or start it with --remote-debugging-port")


# ─── BrowserManager: owns the Playwright + browser + page connection ──────

class BrowserManager:
    """Holds a persistent Playwright connection and current page across tool
    calls. The agent never gets direct CDP access — only the safe tools."""

    def __init__(self):
        self.pw = None
        self.browser = None
        self.page = None
        self._session_guard_active = False
        self._guard_ctx = None  # context with init script

    async def connect(self, cdp_url="", page_url=""):
        """Connect to a browser and get/create a page."""
        if self.page and not self.page.is_closed():
            try:
                _ = self.page.url  # check it's alive
                return self.page
            except Exception:
                self.page = None

        if self.pw is None:
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                raise RuntimeError('pip install "authyouragent[mcp]" (needs playwright)')
            self.pw = await async_playwright().start()

        urls = _cdp_candidates(cdp_url)
        errors = []
        want = page_url.split("#")[0].split("?")[0] if page_url else ""
        for u in urls:
            try:
                self.browser = await self.pw.chromium.connect_over_cdp(u, timeout=8000)
            except Exception as e:
                errors.append(f"{u}: {type(e).__name__}")
                continue
            pages = [pg for ctx in self.browser.contexts for pg in ctx.pages
                     if pg.url.startswith(("http://", "https://"))]
            hit = [pg for pg in pages if want and pg.url.split("#")[0].startswith(want)]
            if hit:
                self.page = hit[-1]
                return self.page
            if pages:
                self.page = pages[-1]
                if not want:
                    return self.page
        if self.page:
            return self.page
        # No existing page — create a new one
        if self.browser:
            ctx = self.browser.contexts[0] if self.browser.contexts else await self.browser.new_context()
            self.page = await ctx.new_page()
            return self.page
        raise RuntimeError("no open web page in the browser" + (f" ({'; '.join(errors)})" if errors else ""))

    async def navigate(self, url):
        page = await self.connect()
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        return page

    async def current_page(self):
        if not self.page or self.page.is_closed():
            await self.connect()
        return self.page

    async def describe(self):
        page = await self.current_page()
        try:
            title = await page.title()
        except Exception:
            title = ""
        return f"{page.url} ({title})" if title else page.url

    def enable_session_guard(self):
        """After takeover: inject script to block cookie reads on every new page."""
        self._session_guard_active = True

    def disable_session_guard(self):
        self._session_guard_active = False

    async def inject_guard_if_active(self):
        """Inject the session guard init script if active. Called after takeover
        and after every navigate."""
        if not self._session_guard_active or not self.browser:
            return
        try:
            for ctx in self.browser.contexts:
                await ctx.add_init_script(_SESSION_GUARD_JS)
        except Exception:
            pass

    async def close(self):
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
        if self.pw:
            try:
                await self.pw.stop()
            except Exception:
                pass
        self.page = None
        self.browser = None
        self.pw = None


def _get_bw():
    global _bw
    if _bw is None:
        _bw = BrowserManager()
    return _bw


# ─── Helpers ──────────────────────────────────────────────────────────────

async def _describe_page():
    return await _get_bw().describe()


NEXT = {
    "done": "The owner finished and handed the browser back. The login session is still "
            "active so you can continue your task on the logged-in page. The MCP server "
            "has injected a session guard that prevents you from reading cookies. When "
            "you are done with the site, call clear_session to wipe the session.",
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
    bw = _get_bw()
    page = await bw.connect(cdp_url, page_url)
    job["url"] = page.url

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
    job["final"] = await _describe_page()
    agent.report_status(f"takeover_{result}", site=page.url.split("/")[2] if "/" in page.url else "")
    # After takeover done: enable session guard so agent cannot read cookies
    if result == "done":
        bw.enable_session_guard()
        await bw.inject_guard_if_active()
    return result


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
        if ctx is not None:
            try:
                await ctx.report_progress(time.time() - job["started"], None)
            except Exception:
                pass
    return (f"result: waiting\ntakeover_id: {job_id}\nThe owner has not finished yet "
            f"({int(time.time() - job['started'])}s so far). Call wait_for_takeover with this "
            f"takeover_id to keep waiting. Do not touch the browser meanwhile.")


# ─── Takeover tools ───────────────────────────────────────────────────────

@mcp.tool()
async def check_login_wall(cdp_url: str = "", page_url: str = "") -> str:
    """Check whether the browser page is stuck at a sign-in, one-time code (2FA) or
    sign-in approval step. Reads form fields and page text only (no screenshot).
    cdp_url: your Chromium's CDP port or URL (optional if the server has a default).
    page_url: which tab, if several are open (optional)."""
    page = await _get_bw().connect(cdp_url, page_url)
    try:
        blocked = await page.evaluate(BLOCKING_JS)
    except Exception:
        blocked = False
    where = await _describe_page()
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
    on the logged-in page. The MCP server injects a session guard that prevents you from
    reading cookies or localStorage. When you are done with the site, call clear_session."""
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
    bw = _get_bw()
    page = await bw.connect(cdp_url, page_url)
    where = await _describe_page()
    await _clear_session(page)
    bw.disable_session_guard()
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


# ─── Browser interaction tools (safe — no cookie/localStorage access) ─────

@mcp.tool()
async def navigate(url: str) -> str:
    """Navigate the browser to a URL. Use this instead of driving the browser directly.
    url: the full URL to navigate to, e.g. "https://example.com"."""
    bw = _get_bw()
    page = await bw.navigate(url)
    await bw.inject_guard_if_active()
    where = await _describe_page()
    return f"navigated to: {where}"


@mcp.tool()
async def click(selector: str) -> str:
    """Click an element on the page by CSS selector.
    selector: a CSS selector for the element to click, e.g. "button.submit" or "#login-btn".
    Returns the page state after clicking."""
    bw = _get_bw()
    page = await bw.current_page()
    try:
        await page.click(selector, timeout=10000)
        where = await _describe_page()
        return f"clicked: {selector}\npage: {where}"
    except Exception as e:
        return f"error: could not click '{selector}': {type(e).__name__}: {e}"


@mcp.tool()
async def type_text(selector: str, text: str, submit: bool = False) -> str:
    """Type text into a form field on the page.
    selector: a CSS selector for the input field, e.g. "input[name=email]".
    text: the text to type into the field.
    submit: set True to press Enter after typing (default False).
    Returns the page state after typing."""
    bw = _get_bw()
    page = await bw.current_page()
    try:
        await page.fill(selector, text, timeout=10000)
        if submit:
            await page.press(selector, "Enter")
        where = await _describe_page()
        return f"typed into: {selector}\npage: {where}"
    except Exception as e:
        return f"error: could not type into '{selector}': {type(e).__name__}: {e}"


@mcp.tool()
async def read_page(max_chars: int = 5000) -> str:
    """Read the current page's text content and URL. Use this to understand what is on
    the page. Returns the page URL, title, and visible text (truncated to max_chars).
    This reads the DOM text only — it does NOT expose cookies, localStorage, or
    sessionStorage.
    max_chars: maximum characters of text to return (default 5000)."""
    bw = _get_bw()
    page = await bw.current_page()
    try:
        title = await page.title()
    except Exception:
        title = ""
    url = page.url
    try:
        text = await page.evaluate("""() => {
            const els = document.querySelectorAll('h1,h2,h3,h4,h5,h6,p,li,button,label,span,a,td,th');
            const seen = new Set();
            const parts = [];
            for (const el of els) {
                const t = el.innerText.trim();
                if (t && !seen.has(t) && t.length < 500) {
                    seen.add(t);
                    parts.push(t);
                }
            }
            return parts.join('\\n');
        }""")
    except Exception:
        text = ""
    if len(text) > max_chars:
        text = text[:max_chars] + "..."
    return f"url: {url}\ntitle: {title}\n\n{text}"


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="authyouragent-mcp",
                                 description="Auth Your Agent Take over MCP server")
    ap.add_argument("--transport", choices=("stdio",), default="stdio")
    ap.parse_args()
    mcp.run("stdio")


if __name__ == "__main__":
    main()