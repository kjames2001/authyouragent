"""Auth Your Agent browser vault: the broker.

Runs inside the vault container next to a normal (headed) Chromium on a
virtual display. The Chromium debug port listens only on the container's own
loopback, so nothing outside the container can attach to the browser or read
its cookies. Agents get a small action API instead (navigate, click, type,
read text, take over, end session).

Session rules, enforced here rather than trusted to the agent:
  * During a take over the agent's automation connection is closed, so the
    site sees an ordinary browser with nothing attached.
  * The session is ended (real sign-out where possible, then the in-memory
    profile is destroyed) when the agent calls end_session, when the agent
    stops sending heartbeats (it crashed or exited), or when the owner
    revokes the agent.

Environment:
  VAULT_TOKEN      bearer token for the action API (required)
  AYA_AGENT_ID     agent id (required for take over and revocation checks)
  AYA_KEY_FILE     agent private key, PEM (default /run/secrets/agent.pem)
  AYA_CLOUD        default https://authyouragent.com
  VAULT_LEASE_S    end the session after this many seconds without a heartbeat (90)
  VAULT_SIZE       page size in CSS pixels, WxH (1280x900)
  VAULT_SCALE      screen pixels per CSS pixel (1). Use 2 or 3 with a phone-sized
                   VAULT_SIZE so the page lays out as on a phone but stays sharp.
"""
import asyncio
import base64
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from urllib.parse import parse_qsl, urlparse

from aiohttp import ClientSession, ClientTimeout, web
from playwright.async_api import async_playwright

import bitwarden
import egress
import trust
from authyouragent.agent import AgentClient
from authyouragent import webbotauth
from authyouragent.takeover import BLOCKING_JS, login_finished

CHROME = shutil.which("chromium") or "/usr/bin/chromium"
CDP = "http://127.0.0.1:9222"
DISPLAY = os.environ.get("DISPLAY", ":0")
PROFILE_ROOT = "/dev/shm"                       # in memory, never on disk
LEASE_S = int(os.environ.get("VAULT_LEASE_S", "90"))
W, H = (int(x) for x in os.environ.get("VAULT_SIZE", "1280x900").split("x"))
if W < 500:     # Chromium will not make a window narrower than 500; keep the shape
    W, H = 500, round(H * 500 / W)
SCALE = float(os.environ.get("VAULT_SCALE", "1"))
TOKEN = os.environ["VAULT_TOKEN"]
WAIT_MAX = 290

# Text blocks in page order, each once. Headings and paragraphs are content
# and are kept whatever their length; a list item or table cell is kept whole
# unless it holds paragraphs of its own (those are read instead). Links,
# buttons, labels and spans can wrap whole sections, so they are only taken
# when short, which keeps a wrapper from repeating everything inside it.
READ_JS = r"""(max) => {
  const out = [], seen = new Set(), taken = new Set();
  let size = 0;
  // Already read as part of a block taken earlier (a link or the per-letter
  // <span>s some pages wrap words in): its text is in that block's line.
  const inTaken = (el) => {
    for (let a = el.parentElement; a; a = a.parentElement) if (taken.has(a)) return true;
    return false;
  };
  for (const el of document.querySelectorAll('h1,h2,h3,h4,h5,h6,p,pre,blockquote,li,dt,dd,button,label,a,td,th,span')) {
    const t = (el.innerText || '').trim();
    if (!t || seen.has(t) || inTaken(el)) continue;
    const tag = el.tagName;
    const block = /^(H[1-6]|P|PRE)$/.test(tag)
      || (/^(LI|TD|TH|DT|DD|BLOCKQUOTE)$/.test(tag) && !el.querySelector('p'));
    if (!block && t.length >= 500) continue;
    seen.add(t); taken.add(el); out.push(t); size += t.length + 1;
    if (size > max) return out.join('\n');
  }
  // Collected everything and it is still a small part of the page: its text
  // sits outside those elements (plain <div>s, a bare text/JSON document).
  // Fall back to everything the page shows rather than reporting it empty.
  const all = ((document.body && document.body.innerText) || '').trim();
  if (all && size < all.length / 4) return all.slice(0, max);
  return out.join('\n');
}"""

# The things on the page an agent can act on, numbered. Each gets a
# data-aya-ref attribute (the previous numbering is cleared first), so click,
# type_text and select_option can take ref=N instead of a guessed selector.
# Open shadow roots are walked (Reddit, many web components); iframes are not.
# A password field's value is never reported.
ELEMENTS_JS = r"""(max) => {
  const SEL = 'a[href],button,input:not([type=hidden]),select,textarea,summary,[contenteditable=""],[contenteditable=true],' +
    '[role=button],[role=link],[role=checkbox],[role=radio],[role=tab],[role=menuitem],[role=switch],' +
    '[role=option],[role=combobox],[role=textbox],[role=searchbox],[tabindex]:not([tabindex="-1"])';
  const roots = [document], all = [];
  for (let i = 0; i < roots.length; i++) {
    for (const el of roots[i].querySelectorAll('*')) {
      if (el.shadowRoot) roots.push(el.shadowRoot);
      if (el.hasAttribute('data-aya-ref')) el.removeAttribute('data-aya-ref');
      if (el.matches(SEL)) all.push(el);
    }
  }
  const text = s => (s || '').replace(/\s+/g, ' ').trim();
  const vh = innerHeight, out = [];
  let n = 0;
  for (let i = 0; i < all.length; i++) {
    const el = all[i];
    if (out.length >= max) break;
    if (el.closest('[aria-hidden=true]') || el.disabled) continue;
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (r.width < 1 || r.height < 1 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    // a clickable wrapper around one already listed (a <div tabindex> around a button)
    if (all[i + 1] && el.contains(all[i + 1]) && !/^(A|BUTTON|SELECT|TEXTAREA|INPUT|SUMMARY)$/.test(el.tagName)
        && !el.getAttribute('role')) continue;
    const tag = el.tagName.toLowerCase(), type = (el.getAttribute('type') || '').toLowerCase();
    const role = el.getAttribute('role') || '';
    let kind = role || tag;
    if (tag === 'input') kind = 'input[' + (type || 'text') + ']';
    if (tag === 'a' && !role) kind = 'link';
    const img = el.querySelector && el.querySelector('img[alt]');
    const lb = el.getAttribute('aria-labelledby');
    const byId = lb ? text(lb.split(/\s+/).map(i => (el.getRootNode().getElementById ? el.getRootNode() : document)
                        .getElementById(i)).filter(Boolean).map(x => x.innerText).join(' ')) : '';
    const inner = el.querySelector && el.querySelector('[aria-label],[title],svg title');
    const innerLabel = inner ? text(inner.getAttribute('aria-label') || inner.getAttribute('title') || inner.textContent) : '';
    let label = text(el.getAttribute('aria-label')) || byId || text(el.innerText).slice(0, 80) ||
                text(el.getAttribute('title')) || (img ? text(img.alt) : '') || innerLabel || text(el.getAttribute('placeholder'));
    if (!label && el.labels && el.labels[0]) label = text(el.labels[0].innerText);
    if (!label && tag === 'input' && /^(submit|button|reset)$/.test(type)) label = text(el.value);
    const item = {ref: ++n, kind, label: label.slice(0, 80)};
    if (el.name) item.name = String(el.name).slice(0, 40);
    if (tag === 'input' && /^(checkbox|radio)$/.test(type)) item.checked = el.checked;
    else if (tag === 'input' && type !== 'password' && !/^(submit|button|reset|file|image)$/.test(type)) item.value = text(el.value).slice(0, 60);
    else if (tag === 'textarea') item.value = text(el.value).slice(0, 60);
    if (tag === 'input' && el.placeholder && el.placeholder !== label) item.placeholder = text(el.placeholder).slice(0, 40);
    if (tag === 'select') {
      item.value = el.selectedOptions[0] ? text(el.selectedOptions[0].text) : '';
      item.options = [...el.options].slice(0, 15).map(o => text(o.text).slice(0, 40));
      if (el.options.length > 15) item.more_options = el.options.length - 15;
    }
    if (tag === 'a') { try { item.href = new URL(el.href).pathname.slice(0, 60); } catch (e) {} }
    if (r.bottom < 0) item.where = 'above';
    else if (r.top > vh) item.where = 'below';
    el.setAttribute('data-aya-ref', String(n));
    out.push(item);
  }
  return {elements: out, total: all.length, scroll: {y: Math.round(scrollY), height: document.documentElement.scrollHeight, view: vh}};
}"""


def _ref_sel(body):
    """The selector for a request: ref=N from the last read_page, or a selector."""
    ref = body.get("ref")
    if ref not in (None, "", 0):
        try:
            n = int(ref)
        except (TypeError, ValueError):
            raise BadRequest("ref must be a number from read_page")
        return f'[data-aya-ref="{n}"]'
    sel = str(body.get("selector") or "")
    if not sel:
        raise BadRequest("give ref (a number from read_page) or selector")
    return sel


async def _find(page, sel):
    if sel.startswith("[data-aya-ref=") and await page.locator(sel).count() == 0:
        raise BadRequest("that ref is not on the page any more; call read_page again")
    await page.locator(sel).first.wait_for(timeout=10000)


# Sign-out routes for providers whose session is worth ending explicitly.
# (url to open, selector of a confirm button if the page asks, url that must
# show a sign-in page afterwards to prove it worked)
SIGNOUT = {
    "google.com": ("https://accounts.google.com/Logout", None,
                   "https://myaccount.google.com/"),
    "github.com": ("https://github.com/logout",
                   'form[action="/logout"] [type=submit]', "https://github.com/settings/profile"),
    "glama.ai": ("https://glama.ai/sign-out", None, "https://glama.ai/settings/preferences"),
    # New Reddit keeps "Log Out" in a lazily built user menu; old Reddit's
    # header has a logout form (POST with the account's modhash).
    "reddit.com": ("https://old.reddit.com/", "form.logout a, form.logout [type=submit]",
                   "https://old.reddit.com/prefs/"),
}
# Where the owner can see and end sessions if a sign-out could not be done.
DEVICE_PAGES = {
    "google.com": "https://myaccount.google.com/device-activity",
    "github.com": "https://github.com/settings/sessions",
    "reddit.com": "https://www.reddit.com/settings/account",
}
# Finds a sign-out control on the page, visible or tucked in a closed menu.
# Returns {href} for a link or {click: true} after clicking a button.
# The words are matched in the site's own language too (a signed-in account
# keeps its language setting), and open shadow roots are searched as well.
LOGOUT_JS = r"""() => {
  const re = new RegExp('^(?:(?:sign|log)\\s?(?:out|off)|登出|退出|退出登录|退出帳號|退出账号|注销|登出帳戶|' +
    'ログアウト|로그아웃|abmelden|ausloggen|se déconnecter|déconnexion|cerrar sesión|' +
    'sair|terminar sessão|esci|disconnetti|uitloggen|wyloguj|выйти|выход|çıkış yap)$', 'iu');
  const words = el => (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').replace(/\s+/g, ' ').trim();
  const all = (sel) => {
    const found = [], roots = [document];
    while (roots.length) {
      const r = roots.shift();
      found.push(...r.querySelectorAll(sel));
      for (const el of r.querySelectorAll('*')) if (el.shadowRoot) roots.push(el.shadowRoot);
    }
    return found;
  };
  for (const a of all('a[href]')) {
    const h = a.getAttribute('href') || '';
    if (/^javascript:/i.test(h)) continue;
    if (re.test(words(a)) || /(^|\/)(log.?out|sign.?out|signoff|logoff)(\b|$)/i.test(h)) return {href: a.href};
  }
  for (const b of all('button,[role=button],[role=menuitem],input[type=submit],a[href^="javascript:" i]')) {
    if (re.test(words(b))) { b.click(); return {click: true}; }
  }
  return null;
}"""
# Mount a volume here to keep the crash record across a hard kill; without one
# the vault works the same but cannot report sites left signed in.
STATE_DIR = os.environ.get("VAULT_STATE_DIR", "/var/lib/vault")
SIGNED_IN_FILE = os.path.join(STATE_DIR, "signed-in.json")      # site names only, never cookies
WBA_KEY_FILE = os.path.join(STATE_DIR, "web-bot-auth.pem")      # this vault's own Web Bot Auth key
# Web Bot Auth: sign every request so websites can recognise this agent. On by
# default; VAULT_WEB_BOT_AUTH=off sends requests unsigned.
WBA_ON = os.environ.get("VAULT_WEB_BOT_AUTH", "on").strip().lower() not in ("0", "off", "false", "no")
WBA_HEADERS = {"signature", "signature-input", "signature-agent"}
LEARNED_FILE = os.path.join(STATE_DIR, "signout-routes.json")   # sign-out urls that worked


def _log(*a):
    print("[vault]", *a, flush=True)


def _site(host):
    host = (host or "").lower()
    if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):     # IP address: the address is the site
        return host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    """Write atomically. The state dir is optional: without it the vault still
    works, it just cannot report after a hard crash."""
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except OSError:
        pass


def _report(agent, status, site, detail):
    """Status line on the owner's dashboard, one per site. Never raises."""
    try:
        r = agent.client.post(f"{agent.base}/api/v1/agent-status", timeout=10, json={
            "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
            "status": status, "site": site, "detail": detail[:280]})
        if r.status_code >= 400:
            _log("status report refused:", r.status_code, r.text[:120])
    except Exception as e:
        _log("status report failed:", e)


def _procs_using(profile):
    pids = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            if profile.encode() in open(f"/proc/{pid}/cmdline", "rb").read():
                pids.append(int(pid))
        except OSError:
            pass
    return pids


def _sweep_profiles():
    """Delete every vault profile in memory (only one browser runs at a time,
    and this is called only while it is stopped)."""
    for name in os.listdir(PROFILE_ROOT):
        if name.startswith("vault-"):
            shutil.rmtree(os.path.join(PROFILE_ROOT, name), ignore_errors=True)


# A sign-in step is recognised by a whole part of the address ("/login",
# "/sessions/two-factor", "/oauth2/v2.0/authorize", "/login.php"), never by
# text inside a longer name: "/kjames2001/authyouragent" or "/authors/jane"
# are ordinary pages.
AUTH_WORD = (r"log.?in|log.?on|sign.?in|sign.?up|oauth2?|auth|authn|authenticate|authori[sz]e|authori[sz]ation|"
             r"sso|saml2?|sessions?|two.?factor|2fa|mfa|otp|totp|verify|verification|challenge|consent")
# a whole segment, optionally with a file ending ("login.php"), or words joined
# by - or _ that are all sign-in words ("mfa-otp-challenge", "sign_in")
AUTH_SEGMENT = re.compile(rf"(({AUTH_WORD})([-_]({AUTH_WORD}))*)(\.[a-z]{{2,5}})?", re.I)
AUTH_HOST = re.compile(r"^(accounts|login|auth|signin|sso|id|identity|appleid|secure)\.", re.I)
SETTLE_S = 2.0


def _is_auth_step(url):
    u = urlparse(url)
    if AUTH_HOST.match(u.hostname or ""):
        return True
    if any(AUTH_SEGMENT.fullmatch(s) for s in u.path.split("/") if s):
        return True
    # "index.php?action=login" style pages (not search terms: "?q=login")
    return any(k.lower() in ("action", "do", "mode", "step", "page", "view", "act") and AUTH_SEGMENT.fullmatch(v)
               for k, v in parse_qsl(u.query))


async def _open_pages():
    """Addresses of the browser's open tabs, from Chromium's local status
    endpoint. Nothing is attached to the pages."""
    async with ClientSession() as s:
        async with s.get(CDP + "/json/list") as r:
            return [t["url"] for t in await r.json() if t.get("type") == "page"]


async def _site_session(ctx, site):
    """The site's HttpOnly cookies (name -> value). Signing in sets or changes
    one of these; just visiting pages normally does not."""
    return {c["name"]: c["value"] for c in await ctx.cookies()
            if c.get("httpOnly") and _site(c["domain"].lstrip(".")) == site}


async def _oidc_end_session(origin):
    """The site's published OpenID Connect sign-out endpoint, if it has one.
    Fetched through the egress filter like any browser request."""
    try:
        async with ClientSession() as s:
            async with s.get(origin + "/.well-known/openid-configuration",
                             proxy=f"http://127.0.0.1:{egress.PORT}", timeout=ClientTimeout(total=8)) as r:
                if r.status == 200:
                    url = (await r.json(content_type=None)).get("end_session_endpoint")
                    if url and urlparse(url).scheme == "https":
                        return url
    except Exception:
        pass
    return None


async def _watch_signin(ws, site, blocked_at_start, cookies_at_start):
    """Hand back automatically once the owner has finished signing in:
      * the page was blocked at the start and that block is gone, or
      * they went through a sign-in step (a sign-in page, or another site
        such as the identity provider) and are back on the site.
    While a sign-in step is on screen nothing is attached. Only once every
    tab is back on the site's own pages does the vault take one short look
    to confirm no password, code or approval prompt is left."""
    went_through_signin = False
    ok_since = None
    while True:
        await asyncio.sleep(0.5)
        try:
            urls = await _open_pages()
        except Exception:
            continue
        on_site = [u for u in urls if _site(urlparse(u).hostname) == site]
        away = [u for u in urls if u not in on_site and not u.startswith(("about:", "chrome"))]
        if away or any(_is_auth_step(u) for u in urls):
            went_through_signin = True
            ok_since = None
            continue
        if not on_site or not (blocked_at_start or went_through_signin):
            ok_since = None
            continue
        now = time.time()
        if ok_since is None:
            ok_since = now
            continue
        if now - ok_since < SETTLE_S:
            continue
        async def look(page):
            if not await login_finished(page):
                return False
            if blocked_at_start:
                return True
            now_c = await _site_session(page.context, site)
            return any(cookies_at_start.get(k) != v for k, v in now_c.items())
        try:
            finished = await V.peek(look)
        except Exception:
            finished = False
        if finished:
            _log("sign-in finished, handing back automatically")
            try:
                await ws.send(json.dumps({"t": "done"}))
            except Exception:
                pass                    # the relay may already be closing; the sign-in still finished
            return True
        ok_since = None                 # still a prompt on the page: keep watching


class BadRequest(Exception):
    pass


class Busy(Exception):
    pass


class Vault:
    def __init__(self):
        self.pw = None
        self.chrome = None
        self.profile = None
        self.browser = None
        self.page = None
        self.used = False            # anything happened since the last wipe
        self.hosts = set()           # main-frame hosts seen while attached
        self.origins = set()         # and their scheme://host:port
        self.last_ping = time.time()
        self.in_takeover = False
        self.lock = asyncio.Lock()
        self.chrome_lock = asyncio.Lock()
        self.jobs = {}
        self._agent = None
        self.wba_key = None          # Ed25519 key, set once the cloud publishes it
        self.wba_agent = None        # Signature-Agent address (https://<label>.agents...)
        self.wba_next = 0

    # ── agent credentials (take over, revocation checks) ──
    def agent(self):
        if self._agent is None:
            aid = os.environ.get("AYA_AGENT_ID")
            kf = os.environ.get("AYA_KEY_FILE", "/run/secrets/agent.pem")
            if not aid or not os.path.exists(kf):
                raise RuntimeError("vault has no agent credentials (AYA_AGENT_ID, AYA_KEY_FILE)")
            self._agent = AgentClient(base_url=os.environ.get("AYA_CLOUD", "https://authyouragent.com"),
                                      agent_id=aid, privkey_pem=open(kf).read())
        return self._agent

    # ── Web Bot Auth ──
    # The vault keeps its own Ed25519 key (never the agent key) in its state
    # directory. The cloud publishes the public half at a per-agent address
    # with this vault's possession proof, and empties that list when the owner
    # revokes the agent. The cloud never sees the signed requests.
    def _wba_load(self, fresh=False):
        if not fresh and os.path.exists(WBA_KEY_FILE):
            try:
                return webbotauth.key_from_pem(open(WBA_KEY_FILE).read())
            except Exception as e:
                _log("web bot auth: unreadable key, making a new one:", type(e).__name__)
        key = webbotauth.new_key()
        try:
            fd = os.open(WBA_KEY_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(webbotauth.key_to_pem(key))
            os.replace(WBA_KEY_FILE + ".tmp", WBA_KEY_FILE)
        except OSError as e:          # no state volume: the key lives until restart
            _log("web bot auth: key not saved:", type(e).__name__)
        return key

    def _wba_publish(self):
        agent = self.agent()
        key = self._wba_load()
        for attempt in (0, 1):
            r = agent.client.post(f"{agent.base}/api/v1/wba/key", json={
                "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
                "jwk": webbotauth.public_jwk(key)})
            if r.status_code == 409 and attempt == 0:      # key belongs to another agent id
                key = self._wba_load(fresh=True)
                continue
            if r.status_code != 200:
                raise RuntimeError(f"key not published ({r.status_code}): {r.text[:160]}")
            break
        info = r.json()
        proof = webbotauth.sign_directory(key, info["directory"].encode(), info["host"])
        r = agent.client.post(f"{agent.base}/api/v1/wba/proof", json={
            "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(), "headers": proof})
        if r.status_code != 200:
            raise RuntimeError(f"proof refused ({r.status_code}): {r.text[:160]}")
        return key, info["signature_agent"]

    async def wba_refresh(self):
        if not WBA_ON or time.time() < self.wba_next:
            return
        try:
            self.agent()
        except Exception:
            self.wba_next = time.time() + 3600        # no agent credentials
            return
        try:
            self.wba_key, self.wba_agent = await asyncio.to_thread(self._wba_publish)
            self.wba_next = time.time() + 2 * 86400   # the proof is good for 7 days
            _log("web bot auth: signing requests as", self.wba_agent)
        except Exception as e:
            self.wba_next = time.time() + 600
            _log("web bot auth not ready:", str(e)[:200])

    # ── browser lifecycle ──
    async def start_chrome(self, url="about:blank", keep_profile=False):
        if not (keep_profile and self.profile):
            self.profile = tempfile.mkdtemp(prefix="vault-", dir=PROFILE_ROOT)
        args = [CHROME, f"--user-data-dir={self.profile}",
                "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=9222",
                "--no-first-run", "--no-default-browser-check", "--password-store=basic",
                "--disable-dev-shm-usage", "--window-position=0,0",
                f"--window-size={W},{H}",      # in page (CSS) pixels, not screen pixels
                # Fill the whole screen with the page: no tab strip or toolbar, and
                # none of the desktop minimum window width that would force a
                # desktop layout onto a phone-sized screen.
                "--kiosk", f"--force-device-scale-factor={SCALE:g}",
                # Every request, loopback included, goes through the egress
                # filter (egress.py): only public internet addresses are reachable.
                f"--proxy-server=http://127.0.0.1:{egress.PORT}", "--proxy-bypass-list=<-loopback>",
                "--disable-quic",
                url]
        # Chromium's sandbox is required. It needs the vault's seccomp profile
        # (docker run --security-opt seccomp=vault/seccomp.json).
        self.chrome = await asyncio.create_subprocess_exec(
            *args, env={**os.environ, "DISPLAY": DISPLAY},
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        async with ClientSession() as s:
            for _ in range(60):
                await asyncio.sleep(0.25)
                try:
                    async with s.get(CDP + "/json/version") as r:
                        if r.status == 200:
                            _log("chromium ready, profile", self.profile)
                            return
                except Exception:
                    pass
        raise RuntimeError("chromium did not start")

    async def ensure_chrome(self):
        """Restart Chromium if it has died (most often because its display was
        killed from outside). The profile is kept, so sign-ins survive."""
        async with self.chrome_lock:
            if self.chrome and self.chrome.returncode is None:
                return
            _log("browser had stopped (exit", self.chrome.returncode if self.chrome else None,
                 "), restarting it")
            await self.detach()
            x = "/tmp/.X11-unix/X" + DISPLAY.lstrip(":").split(".")[0]
            for _ in range(40):                     # the display restarts within ~1s
                if os.path.exists(x):
                    break
                await asyncio.sleep(0.25)
            for pid in _procs_using(self.profile) if self.profile else ():
                try:
                    os.kill(pid, 9)                 # orphaned helpers would hold the profile
                except OSError:
                    pass
            if self.profile:
                for f in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
                    try:
                        os.unlink(os.path.join(self.profile, f))
                    except OSError:
                        pass
            await self.start_chrome(keep_profile=True)

    async def stop_chrome(self):
        await self.detach()
        if self.chrome and self.chrome.returncode is None:
            self.chrome.terminate()
            try:
                await asyncio.wait_for(self.chrome.wait(), 10)
            except asyncio.TimeoutError:
                self.chrome.kill()
                await self.chrome.wait()
        # Chromium's helper processes can outlive the main one and write into
        # the profile as they exit; wait for all of them before deleting.
        if self.profile:
            for _ in range(40):
                if not _procs_using(self.profile):
                    break
                await asyncio.sleep(0.25)
            for pid in _procs_using(self.profile):
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
        _sweep_profiles()
        self.chrome = self.profile = None

    async def relaunch(self, url):
        """Restart the browser on `url`, keeping the profile (used by the
        owner's "Start again" during a take over; nothing gets attached)."""
        if self.chrome and self.chrome.returncode is None:
            self.chrome.terminate()
            try:
                await asyncio.wait_for(self.chrome.wait(), 10)
            except asyncio.TimeoutError:
                self.chrome.kill()
                await self.chrome.wait()
        for _ in range(40):
            if not _procs_using(self.profile):
                break
            await asyncio.sleep(0.25)
        await self.start_chrome(url, keep_profile=True)

    async def attach(self):
        if self.in_takeover:
            raise Busy("the owner is in control of the browser (take over in progress)")
        await self.ensure_chrome()
        if self.browser and self.browser.is_connected() and self.page and not self.page.is_closed():
            return self.page
        await self.detach()
        self.browser = await self.pw.chromium.connect_over_cdp(CDP)
        ctx = self.browser.contexts[0]
        self.page = ctx.pages[-1] if ctx.pages else await ctx.new_page()
        for p in ctx.pages:
            await self._oidc_hook(p)
        ctx.on("page", lambda p: asyncio.ensure_future(self._oidc_hook(p)))
        self.page.on("framenavigated", self._on_nav)
        self._on_nav(self.page.main_frame)
        return self.page

    # ── Sign in with Auth Your Agent ──
    # When a site's "Sign in with Auth Your Agent" sends the browser to the
    # cloud's /oidc/authorize, the vault adds the agent's proof: a short JWT
    # signed with the agent key and bound to that exact address. The browser
    # usually arrives there through the site's redirect, which Playwright's
    # route does not see, so this uses CDP Fetch on each page directly.
    # Only the configured cloud's authorize address gets the header.
    async def _oidc_hook(self, page):
        try:
            agent = self.agent()
        except Exception:
            return                      # no agent credentials: nothing to add
        cloud = urlparse(agent.base)
        prefix = f"{cloud.scheme}://{cloud.netloc}/oidc/authorize"
        try:
            cdp = await page.context.new_cdp_session(page)
        except Exception as e:
            _log(f"oidc hook not installed: {type(e).__name__}")
            return

        async def paused(ev):
            req = ev["request"]
            # A page cannot supply these itself: the vault alone adds them.
            hs = [{"name": k, "value": v} for k, v in req["headers"].items()
                  if k.lower() != "x-authyouragent-agent" and k.lower() not in WBA_HEADERS]
            u = urlparse(req["url"])
            if (f"{u.scheme}://{u.netloc}{u.path}" == prefix and req["method"] == "GET"
                    and ev.get("resourceType") == "Document"):
                hs.append({"name": "X-AuthYourAgent-Agent", "value": agent.oidc_header(req["url"])})
                self.used = True
                _log(f"sign in with Auth Your Agent: proof added for {u.netloc}")
            if self.wba_key and self.wba_agent and u.scheme in ("http", "https"):
                try:
                    for k, v in webbotauth.sign_request(self.wba_key, req["method"], req["url"],
                                                        self.wba_agent).items():
                        hs.append({"name": k, "value": v})
                except Exception as e:
                    _log("web bot auth: request not signed:", type(e).__name__)
            try:
                await cdp.send("Fetch.continueRequest", {"requestId": ev["requestId"], "headers": hs})
            except Exception:
                pass

        cdp.on("Fetch.requestPaused", lambda ev: asyncio.ensure_future(paused(ev)))
        pattern = ({"urlPattern": "*", "requestStage": "Request"} if WBA_ON else
                   {"urlPattern": prefix + "*", "resourceType": "Document", "requestStage": "Request"})
        await cdp.send("Fetch.enable", {"patterns": [pattern]})

    def _on_nav(self, frame):
        if self.page and frame == self.page.main_frame:
            u = urlparse(frame.url)
            if u.hostname and u.scheme in ("http", "https"):
                self.hosts.add(u.hostname)
                self.origins.add(f"{u.scheme}://{u.netloc}")

    async def peek(self, fn):
        """Attach for one short look while the owner is in control, then let go.
        Used only on the site's own pages, never on a sign-in step."""
        await self.ensure_chrome()
        browser = await self.pw.chromium.connect_over_cdp(CDP)
        try:
            ctx = browser.contexts[0]
            return await fn(ctx.pages[-1]) if ctx.pages else None
        finally:
            try:
                await browser.close()
            except Exception:
                pass

    async def detach(self):
        """Close the automation connection. The browser keeps running."""
        if self.browser:
            try:
                await self.browser.close()      # over CDP this only disconnects
            except Exception:
                pass
        self.browser = self.page = None

    # ── ending a session ──
    async def sign_out(self):
        """Try a real sign-out on every site used in this session. Returns a
        per-site report; never claims success it has not checked."""
        report = {}
        page = await self.attach()
        cookie_sites = {_site(c["domain"].lstrip(".")) for c in await page.context.cookies()}
        # The agent is detached while the owner is in control, so sites the owner
        # visited are not in self.hosts. Always include the known sign-in
        # providers whenever the browser holds their cookies.
        sites = ({_site(h) for h in self.hosts} | set(SIGNOUT)) & cookie_sites
        for site in sorted(sites):
            try:
                report[site] = await self._sign_out_site(page, site)
            except Exception as e:
                report[site] = f"error: {type(e).__name__}"
        return report

    async def _sign_out_site(self, page, site):
        if site in SIGNOUT:
            url, confirm, probe = SIGNOUT[site]
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            if confirm and await page.locator(confirm).count():
                await page.locator(confirm).first.click()
                await page.wait_for_load_state("domcontentloaded")
            # A signed-out visit to the probe page is sent to a sign-in page or
            # away from the probe's host (myaccount.google.com -> google.com/account/about).
            await page.goto(probe, wait_until="domcontentloaded", timeout=20000)
            await asyncio.sleep(1)
            final = urlparse(page.url)
            if (final.hostname != urlparse(probe).hostname or not await login_finished(page)
                    or re.search(r"sign.?in|login", final.path, re.I)):
                return "signed out (checked)"
            return "sign-out attempted, still signed in"
        return await self._sign_out_generic(page, site)

    async def _sign_out_generic(self, page, site):
        """Sites without a known route. In order: a route that worked before,
        the site's published OpenID sign-out endpoint, then a sign-out control
        on its own pages. Checked by whether the site cleared its session
        cookies (a server that ends the session clears them)."""
        before = await _site_session(page.context, site)
        origin = next((o for o in self.origins if _site(urlparse(o).hostname) == site), f"https://{site}")
        learned = _load(LEARNED_FILE, {})
        tried = []

        async def settled():
            await asyncio.sleep(1.5)
            after = await _site_session(page.context, site)
            return bool(before) and all(after.get(k) != v for k, v in before.items())

        async def confirm_if_asked():
            btn = page.get_by_role("button", name=re.compile(r"^(sign|log)\s?(out|off)|^yes|^confirm|^continue", re.I))
            if await btn.count():
                await btn.first.click()
                await page.wait_for_load_state("domcontentloaded")

        async def via(url, how):
            tried.append(how)
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            await confirm_if_asked()
            if await settled():
                learned[site] = url
                _save(LEARNED_FILE, learned)
                return True
            return False

        if site in learned and await via(learned[site], "learned route"):
            return "signed out (checked: session cookie cleared)"
        end = await _oidc_end_session(origin)
        if end and await via(end, "OpenID sign-out"):
            return "signed out (checked: session cookie cleared)"
        tried.append("page control")
        await page.goto(origin + "/", wait_until="domcontentloaded", timeout=20000)
        found = await page.evaluate(LOGOUT_JS)
        if found and found.get("href"):
            if await via(found["href"], "sign-out link"):
                return "signed out (checked: session cookie cleared)"
        elif found:
            await page.wait_for_load_state("domcontentloaded")
            await confirm_if_asked()
            if await settled():
                return "signed out (checked: session cookie cleared)"
        if not before:
            return "no sign-in cookie found (nothing to sign out)"
        if not found and not end and site not in learned:
            return "no sign-out found; wiped locally, not signed out"
        return "sign-out attempted, not confirmed; wiped locally"

    async def end_session(self, why):
        """Sign out, then destroy the profile and start a fresh browser.
        Ending a session always wins over a take over in progress: the owner's
        control is ended first so the sign-out can run."""
        for jid, job in list(self.jobs.items()):
            if not job["task"].done():
                job["task"].cancel()
                try:
                    await job["task"]
                except (asyncio.CancelledError, Exception):
                    pass
            self.jobs.pop(jid, None)
        self.in_takeover = False
        async with self.lock:
            report = {}
            if self.used:
                try:
                    report = await asyncio.wait_for(self.sign_out(), 90)
                except Exception as e:
                    report = {"*": f"sign-out failed: {type(e).__name__}"}
            await self.stop_chrome()
            await self.start_chrome()
            self.used, self.hosts, self.origins = False, set(), set()
            trust.reset()
            _save(SIGNED_IN_FILE, [])
            _log("session ended:", why, report)
            for site, result in report.items():
                await asyncio.to_thread(_report, self.agent(), "session_cleared", site, f"{why}: {result}")
            return report

    # ── crash record ──
    async def record_signed_in(self):
        """Keep the list of sites with sign-in cookies on disk (names only), so
        a vault that was killed before it could sign out can say so."""
        try:
            page = await self.attach()
            sites = sorted({_site(c["domain"].lstrip(".")) for c in await page.context.cookies()
                            if c.get("httpOnly")})
        except Exception:
            return
        _save(SIGNED_IN_FILE, sites)

    def report_crash(self):
        """At startup: sites left signed in by a vault that did not shut down
        cleanly. Their cookies are gone (the profile lived in memory), but the
        sessions are still valid on the sites' side until they expire."""
        left = _load(SIGNED_IN_FILE, [])
        if not left:
            return
        pages = {s: DEVICE_PAGES.get(s, f"https://{s}") for s in left}
        _log("previous session ended without sign-out; still signed in on the sites' side:", pages)
        for site, page in pages.items():
            _report(self.agent(), "session_not_signed_out", site,
                    f"The vault stopped before it could sign out. End the session at {page}")
        _save(SIGNED_IN_FILE, [])

    # ── watchdogs ──
    async def watchdog(self):
        last_status = 0
        last_record = 0
        while True:
            await asyncio.sleep(5)
            await self.wba_refresh()
            if not self.in_takeover and self.chrome and self.chrome.returncode is not None:
                try:
                    await self.ensure_chrome()
                except Exception as e:
                    _log("browser restart failed:", e)
            if self.used and not self.in_takeover and time.time() - last_record > 15:
                last_record = time.time()
                await self.record_signed_in()
            if not self.used or self.in_takeover:
                continue
            if time.time() - self.last_ping > LEASE_S:
                await self.end_session("agent stopped sending heartbeats")
                continue
            if time.time() - last_status > 30:
                last_status = time.time()
                try:
                    st = await asyncio.to_thread(self.agent().check_status)
                    if st.get("status") == "revoked":
                        await self.end_session("agent revoked by the owner")
                except Exception as e:
                    _log("status check failed:", e)


V = Vault()


# ── HTTP API ──
@web.middleware
async def auth(request, handler):
    if request.headers.get("Authorization") != f"Bearer {TOKEN}":
        return web.json_response({"error": "unauthorized"}, status=401)
    V.last_ping = time.time()
    try:
        return await handler(request)
    except Busy as e:
        return web.json_response({"error": "busy", "detail": str(e)}, status=409)
    except NotApproved as e:
        return web.json_response({"error": "not_approved", "detail": str(e)}, status=403)
    except BadRequest as e:
        return web.json_response({"error": "bad_request", "detail": str(e)}, status=400)
    except Exception as e:
        if "ERR_BLOCKED_BY_ADMINISTRATOR" in str(e) or "ERR_TUNNEL_CONNECTION_FAILED" in str(e):
            return web.json_response({"error": "blocked", "detail":
                "blocked by the vault: only public websites can be opened"}, status=403)
        return web.json_response({"error": type(e).__name__, "detail": str(e)[:300]}, status=500)


async def _where(page):
    try:
        title = await page.title()
    except Exception:
        title = ""
    return {"url": page.url, "title": title}


async def status(request):
    return web.json_response({"attached": bool(V.browser), "in_takeover": V.in_takeover,
                              "session_active": V.used, "lease_s": LEASE_S,
                              "web_bot_auth": V.wba_agent if V.wba_key else None,
                              "trusted_sites": trust.entries()})


async def ping(request):
    return web.json_response({"ok": True})


async def navigate(request):
    body = await request.json()
    url = str(body.get("url", ""))
    if not url.startswith(("http://", "https://")):
        return web.json_response({"error": "url must start with http:// or https://"}, status=400)
    page = await V.attach()
    V.used = True
    host, port = _hostport(url)
    pkey = trust.private_key(host, port)
    if pkey and not await _trust_ok(page, pkey, "trusted_site:open_on_your_network_this_session",
                                    site=re.sub(r"[^a-z0-9.-]", "", host) or "private"):
        return web.json_response({"error": "blocked", "detail":
            f"blocked by the vault: the owner has not confirmed {pkey} on their phone this session"}, status=403)
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        # After a blocked page the tab can still be settling on Chromium's error
        # page, which interrupts the next navigation. Try once more.
        if "interrupted by another navigation" not in str(e):
            raise
        await asyncio.sleep(0.5)
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    # Plain http:// goes through the egress filter as a normal request, so a
    # refusal arrives as a page, not a network error. Report it as one.
    if resp is not None and resp.headers.get("x-vault-blocked"):
        await page.goto("about:blank")
        return web.json_response({"error": "blocked", "detail":
            "blocked by the vault: only public websites, and private hosts the owner trusted, can be opened"},
            status=403)
    return web.json_response(await _where(page))


# ── Step-up approval ──
# Clicks (and Enter in a form) that commit something need the owner's approval
# on their phone first. The vault asks and waits itself; the agent cannot skip
# it because every click goes through here. One approval covers one action.
SENSITIVE = re.compile(
    r"\b(submit|send|post|publish|share|delete|remove|erase|destroy|cancel (my )?(account|subscription|order)|"
    r"close account|deactivate|pay|purchase|buy|order|checkout|check out|place order|subscribe|upgrade|donate|"
    r"transfer|withdraw|confirm|approve|accept|authori[sz]e|grant|allow|invite|add (member|user|collaborator)|"
    r"make public|change (password|email)|reset|merge|deploy|release|save changes?|update (password|email|payment)|"
    r"create|comment|reply|save|update|rename|archive|reopen|block|report|book|reserve|"
    r"close (issue|pull request|account)|apply (now|for)|leave (group|team|organi[sz]ation)|"
    r"add (comment|reply|review|key|email|account|payment|card|address))\b",
    re.I)
# Labels that never need approval: steps of signing in, searching, cookie banners.
# Names of pages, not actions: "Release history" is a tab, "Release payment" asks.
HARMLESS = re.compile(r"^(sign|log) ?(in|up)$|^continue$|^next$|^search|cookie|"
                      r"^(release|order|comment|report|booking|reservation)s? (history|notes|list|details)$", re.I)
EXTRA = [w.strip() for w in os.environ.get("VAULT_APPROVE_WORDS", "").split(",") if w.strip()]
APPROVAL_WAIT = 290

TARGET_JS = r"""(el) => {
  const text = s => (s || '').replace(/\s+/g, ' ').trim();
  // The words on a button, without keyboard-shortcut hints that sites put
  // inside it (GitHub: "Create ( control ⌃ enter ⏎ )").
  const words = b => {
    let t = b.innerText || '';
    for (const k of b.querySelectorAll('kbd,[aria-hidden=true]')) {
      const s = (k.innerText || '').trim();
      if (s) t = t.replace(s, ' ');
    }
    t = t.replace(/\(([^()]*?)\)/g, (m, inner) =>
      /^[\s]*$/.test(inner) || /control|ctrl|cmd|command|shift|enter|return|option|alt\b|[⌘⌃⇧⏎⌥↵]/i.test(inner) ? ' ' : m);
    t = text(t.replace(/[⌘⌃⇧⏎⌥↵]/g, ' '));
    return t || text(b.innerText);
  };
  const btn = el.closest('button,a,[role=button],input[type=submit],input[type=button]') || el;
  const form = btn.form || btn.closest('form');
  const label = text(words(btn) || btn.value || btn.getAttribute('aria-label') || btn.title);
  const isSubmit = !!form && (btn.type === 'submit' || (btn.tagName === 'BUTTON' && !btn.getAttribute('type')));
  let formSubmit = '';
  if (form) {
    const b = form.querySelector('button[type=submit],button:not([type]),input[type=submit]');
    formSubmit = b ? text(words(b) || b.value || b.getAttribute('aria-label')) : '';
  }
  // A form with exactly one password field is a sign-in form (a password
  // change has two or more).
  const secrets = form ? form.querySelectorAll('input[type=password]').length : 0;
  // Search and filter forms change nothing. Only an explicit method="get" counts:
  // script-driven forms often leave method out and post with fetch.
  // A form whose only text field is named q / query / search is a search box
  // even when it posts (DuckDuckGo's HTML search does).
  const fields = form ? [...form.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]),textarea,select')] : [];
  const searchField = fields.length === 1 && /^(q|query|search|search_query|keywords?|s)$/i.test(fields[0].name || '');
  const searchForm = !!form && ((form.getAttribute('method') || '').toLowerCase() === 'get'
    || form.getAttribute('role') === 'search' || !!form.closest('[role=search]')
    || !!form.querySelector('input[type=search]') || /search/i.test(form.getAttribute('action') || '')
    || /(^|[\s_-])search([\s_-]|$)/i.test(form.id + ' ' + form.className) || searchField);
  return {label: label.slice(0, 80), isSubmit, inForm: !!form, formSubmit: formSubmit.slice(0, 80),
          signIn: secrets === 1, searchForm};
}"""


def _needs_approval(label, submits_form=False):
    """True when the action commits something: its wording says so, or it
    submits a form (whatever the wording). Callers exempt sign-in and search."""
    if label and HARMLESS.search(label):
        return False
    if submits_form:
        return True
    return bool(label) and bool(SENSITIVE.search(label) or any(w.lower() in label.lower() for w in EXTRA))


async def _approve(page, label, site=None):
    """Ask the owner, on their phone, to approve `label` on this site. Returns
    approved / denied / expired / cancelled."""
    agent = V.agent()
    site = site or _site(urlparse(page.url).hostname)
    action = re.sub(r"[^a-z0-9_:-]", "", label.lower().replace(" ", "_"))[:64] or "action"
    r = await asyncio.to_thread(agent.client.post, f"{agent.base}/api/v1/agent-approval", json={
        "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(), "site": site, "action": action})
    if r.status_code != 200:
        raise RuntimeError(f"approval request refused: {r.status_code} {r.text[:200]}")
    txn = r.json()["txn_id"]
    _log("approval requested:", site, action, txn)
    deadline = time.time() + APPROVAL_WAIT
    while time.time() < deadline:
        await asyncio.sleep(3)
        V.last_ping = time.time()        # waiting on the owner is not the agent going away
        try:
            g = await asyncio.to_thread(agent.client.get, f"{agent.base}/api/v1/authz-requests/{txn}")
            st = g.json().get("status") if g.status_code == 200 else None
        except Exception:
            st = None
        if st in ("approved", "denied", "expired", "cancelled"):
            _log("approval", st, action)
            return st
    return "expired"


class NotApproved(Exception):
    pass


# A click the page and button do not show as committing can still send data
# from a script. While such a click runs, requests that write to the site are
# held until the owner decides. Not held: reads, beacons, analytics endpoints,
# read-only GraphQL, and other sites (on most pages those are analytics).
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
TELEMETRY = re.compile(r"/(collect|stats|telemetry|analytics|metrics|beacon|events?|log|logs|logging|"
                       r"track(ing)?|rum|csp-report|report-uri|_private/browser)(/|$|\?)|\bgen_204\b", re.I)
WATCH_S = 2.0               # grace after the click: a first write must land within this
WATCH_TAIL_S = 0.6          # keep watching this long after the LAST write (a cascade of saves)
WATCH_CAP_S = 8.0           # never hold a click longer than this, no matter what


def _is_write(req, page_site):
    if req.method.upper() not in WRITE_METHODS or req.resource_type in ("ping", "beacon"):
        return False
    u = urlparse(req.url)
    if _site(u.hostname) != page_site or TELEMETRY.search(u.path):
        return False
    if re.search(r"graphql", u.path, re.I):
        body = req.post_data or ""
        return bool(re.search(r"\bmutation\b", body))
    return True


async def _watched(page, label, act):
    """Run `act()`; hold scripted writes to the site and ask the owner once for
    all of them. A first write must start within WATCH_S of the click; after
    it, writes keep being held until the page has been quiet for WATCH_TAIL_S
    (a run of saves is asked about as one), at most WATCH_CAP_S in all."""
    site = _site(urlparse(page.url).hostname)
    decision = None                      # future: "approved" / other
    held = asyncio.Event()
    settled = []                         # one task per held request, done once it is aborted or let through
    last_write = [0.0]                   # monotonic time of the most recent held write
    t0 = time.monotonic()

    async def handler(route, req):
        nonlocal decision
        if not _is_write(req, site):
            return await route.fallback()
        last_write[0] = time.monotonic()        # every write restarts the quiet tail
        if decision is None:
            decision = asyncio.get_running_loop().create_future()
            held.set()
        settled.append(asyncio.current_task())
        result = await decision
        if result == "approved":
            await route.fallback()
        else:
            await route.abort("blockedbyclient")

    await page.route("**/*", handler)
    try:
        await act()
        try:
            await asyncio.wait_for(held.wait(), WATCH_S)
        except asyncio.TimeoutError:
            return
        # wait for the page to go quiet, so a run of writes is one question
        while (time.monotonic() - last_write[0] < WATCH_TAIL_S
               and time.monotonic() - t0 < WATCH_CAP_S):
            await asyncio.sleep(0.05)
        what = f"{label or 'button'} (sends data to the site)"
        result = await _approve(page, what)
        decision.set_result(result)
        if result != "approved":
            raise NotApproved(f"the owner did not approve '{what}' ({result}); "
                              "the page's request was blocked")
    finally:
        if decision is not None and not decision.done():
            decision.set_result("cancelled")
        # Let every held request be aborted (or let through) before the route
        # goes: removing it first turns interception off, and Chromium then
        # sends the paused request anyway.
        pending = [t for t in settled if t is not asyncio.current_task() and not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=5)
        await page.unroute("**/*", handler)


def _hostport(url):
    u = urlparse(url)
    return (u.hostname or "").lower(), u.port or {"https": 443, "http": 80}.get(u.scheme)


async def _trust_ok(page, key, what, site=None):
    """True once the owner has confirmed a trusted-site entry this session.
    Asks them once; a refusal is remembered until the entry or session changes."""
    if trust.confirmed(key):
        return True
    if trust.declined(key):
        return False
    result = await _approve(page, what, site=site)
    if result == "approved":
        trust.confirm(key)
        _log("trusted site confirmed:", key)
        return True
    trust.decline(key)
    return False


async def _trusted(page):
    """Clicks on this site skip per-click approval: the owner listed it with
    "approvals": false and confirmed that on their phone this session."""
    host, port = _hostport(page.url)
    key = trust.approvals_key(host, port, _site(host))
    # The phone card shows the site plus this action (the cloud keeps [a-z0-9_:-] only)
    return bool(key) and await _trust_ok(page, key, "trusted_site:no_click_approvals_this_session",
                                         site=re.sub(r"[^a-z0-9.-]", "", key.split(":")[0]))


async def _guarded(page, selector, label_of, act, submits_form):
    """Run `act()` only after the owner approves, if the target commits something."""
    if await _trusted(page):
        return await act()
    info = await page.locator(selector).first.evaluate(TARGET_JS)
    label = label_of(info)
    sign_in = info["signIn"] and not re.search(r"change|update|reset|new password", label, re.I)
    # Any form submit asks, except search forms and the steps of signing in
    # (codes, "Verify"). On sign-in pages the wording rule still applies, so an
    # OAuth "Authorize" or "Allow" button still asks the owner.
    form_rule = submits_form(info) and not info["searchForm"] and not _is_auth_step(page.url)
    if not sign_in and _needs_approval(label, form_rule):
        label = label or "submit form"
        result = await _approve(page, label)
        if result != "approved":
            raise NotApproved(f"the owner did not approve '{label}' ({result})")
        return await act()
    if sign_in or info["searchForm"] or _is_auth_step(page.url):
        return await act()
    # Not shown as committing: watch what the click actually sends.
    await _watched(page, label, act)


async def click(request):
    body = await request.json()
    page = await V.attach()
    sel = _ref_sel(body)
    await _find(page, sel)
    await _guarded(page, sel, lambda i: i["label"],
                   lambda: page.click(sel, timeout=10000),
                   lambda i: i["isSubmit"])
    await asyncio.sleep(0.5)
    return web.json_response(await _where(page))


async def type_text(request):
    body = await request.json()
    page = await V.attach()
    sel = _ref_sel(body)
    await _find(page, sel)
    await page.fill(sel, str(body.get("text", "")), timeout=10000)
    if body.get("submit"):
        # Enter submits the field's form: same rule as clicking its submit button
        await _guarded(page, sel, lambda i: i["formSubmit"],
                       lambda: page.press(sel, "Enter"),
                       lambda i: i["inForm"])
        await asyncio.sleep(0.5)
    return web.json_response(await _where(page))


async def read(request):
    n = max(200, min(int(request.query.get("max_chars", 5000)), 20000))
    m = max(0, min(int(request.query.get("max_elements", 80)), 300))
    page = await V.attach()
    text = await page.evaluate(READ_JS, n)
    out = {**await _where(page), "text": text[:n]}
    if m:
        out.update(await page.evaluate(ELEMENTS_JS, m))
    return web.json_response(out)


# Keys an agent may press. Enter and Space can submit or press a button, so
# they go through the same approval rules as a click on the focused element.
KEYS = {"Enter", "Space", "Tab", "Shift+Tab", "Escape", "Backspace", "Delete", "ArrowUp", "ArrowDown",
        "ArrowLeft", "ArrowRight", "PageUp", "PageDown", "Home", "End"}
FOCUS_TAG_JS = r"""() => {
  let e = document.activeElement;
  while (e && e.shadowRoot && e.shadowRoot.activeElement) e = e.shadowRoot.activeElement;
  for (const o of document.querySelectorAll('[data-aya-focus]')) o.removeAttribute('data-aya-focus');
  if (!e || e === document.body || e === document.documentElement) return null;
  e.setAttribute('data-aya-focus', '1');
  return {tag: e.tagName, type: (e.getAttribute('type') || 'text').toLowerCase()};
}"""


async def press(request):
    body = await request.json()
    key = str(body.get("key", ""))
    if key not in KEYS:
        raise BadRequest("key must be one of: " + ", ".join(sorted(KEYS)))
    page = await V.attach()
    V.used = True
    pw_key = " " if key == "Space" else key
    if body.get("ref") or body.get("selector"):
        sel = _ref_sel(body)
        await _find(page, sel)
        await page.focus(sel, timeout=10000)
    act = lambda: page.keyboard.press(pw_key)
    if key in ("Enter", "Space"):
        f = await page.evaluate(FOCUS_TAG_JS)
        if f is None:
            if await _trusted(page):
                await act()
            else:
                await _watched(page, f"press {key}", act)
        elif key == "Enter" and f["tag"] == "INPUT" and f["type"] not in ("submit", "button", "checkbox", "radio"):
            await _guarded(page, "[data-aya-focus]", lambda i: i["formSubmit"], act, lambda i: i["inForm"])
        elif key == "Enter" and f["tag"] == "TEXTAREA":
            await act()                  # a new line
        else:
            await _guarded(page, "[data-aya-focus]", lambda i: i["label"], act, lambda i: i["isSubmit"])
    else:
        await act()
    await asyncio.sleep(0.3)
    return web.json_response(await _where(page))


async def select(request):
    body = await request.json()
    option = str(body.get("option", ""))
    if not option:
        raise BadRequest("option: the text of the choice, as listed by read_page")
    page = await V.attach()
    V.used = True
    sel = _ref_sel(body)
    await _find(page, sel)
    act = lambda: page.select_option(sel, label=option, timeout=10000)
    # Choosing can submit the form from a script (onchange): watch what it sends.
    if await _trusted(page):
        await act()
    else:
        await _watched(page, f"choose {option[:40]}", act)
    await asyncio.sleep(0.3)
    return web.json_response(await _where(page))


SCROLL_JS = r"""(dir) => {
  const before = scrollY, h = innerHeight;
  if (dir === 'top') scrollTo(0, 0);
  else if (dir === 'bottom') scrollTo(0, document.documentElement.scrollHeight);
  else scrollBy(0, (dir === 'up' ? -1 : 1) * Math.round(h * 0.85));
  return {moved: Math.round(scrollY - before)};
}"""


async def scroll(request):
    body = await request.json()
    page = await V.attach()
    if body.get("ref") or body.get("selector"):
        sel = _ref_sel(body)
        await _find(page, sel)
        await page.locator(sel).first.scroll_into_view_if_needed(timeout=10000)
        moved = None
    else:
        d = str(body.get("direction", "down"))
        if d not in ("down", "up", "top", "bottom"):
            raise BadRequest("direction must be down, up, top or bottom")
        moved = (await page.evaluate(SCROLL_JS, d))["moved"]
        await page.mouse.wheel(0, 1 if d in ("down", "bottom") else -1)   # wake lazy loaders
    await asyncio.sleep(0.6)       # let infinite lists load
    pos = await page.evaluate("() => ({y: Math.round(scrollY), height: document.documentElement.scrollHeight, "
                              "view: innerHeight})")
    return web.json_response({**await _where(page), "moved": moved, "scroll": pos,
                              "at_end": pos["y"] + pos["view"] >= pos["height"] - 2})


async def back(request):
    page = await V.attach()
    # go_back's response is None both when there is no history and when Chrome
    # restores the page from its back/forward cache, so compare the history
    # position instead.
    # A page restored from that cache never fires domcontentloaded, so wait
    # only for the navigation to commit, then give a fresh load a moment.
    before = await page.evaluate("() => location.href")
    await page.go_back(wait_until="commit", timeout=30000)
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception:
        pass
    after = await page.evaluate("() => location.href")
    return web.json_response({**await _where(page), "moved": after != before})


async def wait_for(request):
    body = await request.json()
    secs = max(1, min(float(body.get("seconds", 10)), 30))
    page = await V.attach()
    want = str(body.get("text") or "")
    try:
        if want:
            await page.get_by_text(want).first.wait_for(state="visible", timeout=secs * 1000)
        elif body.get("selector"):
            await page.locator(str(body["selector"])).first.wait_for(state="visible", timeout=secs * 1000)
        elif body.get("gone"):
            await page.get_by_text(str(body["gone"])).first.wait_for(state="hidden", timeout=secs * 1000)
        else:
            await page.wait_for_load_state("networkidle", timeout=secs * 1000)
        found = True
    except Exception as e:
        if "Timeout" not in type(e).__name__ and "imeout" not in str(e):
            raise
        found = False
    return web.json_response({**await _where(page), "found": found})


async def screenshot(request):
    page = await V.attach()
    full = request.query.get("full") == "1"
    img = await page.screenshot(type="jpeg", quality=60, full_page=full, timeout=15000)
    if full and len(img) > 1_500_000:
        img = await page.screenshot(type="jpeg", quality=40, full_page=False, timeout=15000)
    return web.json_response({**await _where(page), "jpeg_b64": base64.b64encode(img).decode()})


# ── Stored secrets (the owner's Bitwarden / Vaultwarden) ──
# The agent names an item; the vault types its value into one field and never
# returns it. A value is filled only on an address saved with the item (same
# scheme, host and port), only into the page's own top frame, and only into a
# field of the right kind: a password into a password field, a code into a
# short one-time-code field, a username into a single-line input. So it cannot
# be typed into a comment box or a look-alike site.
FIELD_JS = r"""(el) => {
  const top = window === window.top;
  const tag = el.tagName, type = (el.getAttribute('type') || 'text').toLowerCase();
  const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
  const hint = [el.name, el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'), ac]
    .join(' ').toLowerCase();
  const max = el.maxLength > 0 ? el.maxLength : 0;
  return {top, origin: location.origin, tag, type, ac, hint, max,
          inputmode: (el.getAttribute('inputmode') || '').toLowerCase(),
          editable: !el.disabled && !el.readOnly};
}"""
CODE_HINT = re.compile(r"one-time-code|otp|totp|2fa|mfa|two.?factor|verif|auth.?code|security.?code|\bcode\b|token|pin", re.I)


def _field_ok(f, field):
    if not f["top"]:
        return "the field is inside a frame; secrets are filled only in the page itself"
    if f["tag"] != "INPUT" or not f["editable"]:
        return "not an editable input field"
    if field == "password":
        return None if f["type"] == "password" else "a password goes only into a password field"
    if field == "totp":
        if f["type"] not in ("text", "tel", "number", "password"):
            return "not a code field"
        if f["ac"] == "one-time-code" or (CODE_HINT.search(f["hint"]) and (f["max"] == 0 or f["max"] <= 10)):
            return None
        return "this does not look like a one-time code field"
    if field == "username":
        return None if f["type"] in ("text", "email", "tel") else "a username goes only into a text or email field"
    return "unknown field"


async def list_secrets(request):
    try:
        return web.json_response({"items": await bitwarden.STORE.list()})
    except bitwarden.SecretsError as e:
        return web.json_response({"error": "secrets", "detail": str(e)}, status=400)


async def fill_secret(request):
    body = await request.json()
    name, field, sel = str(body.get("name", "")), str(body.get("field", "password")), _ref_sel(body)
    if field not in ("username", "password", "totp"):
        return web.json_response({"error": "secrets", "detail": "field must be username, password or totp"}, status=400)
    page = await V.attach()
    V.used = True
    await _find(page, sel)
    el = await page.locator(sel).first.element_handle(timeout=10000)
    f = await el.evaluate(FIELD_JS)
    if f["origin"] != f"{urlparse(page.url).scheme}://{urlparse(page.url).netloc}":
        return web.json_response({"error": "secrets", "detail": "the field is not on this page"}, status=400)
    why = _field_ok(f, field)
    if why:
        return web.json_response({"error": "secrets", "detail": why}, status=400)
    try:
        value = await bitwarden.STORE.value(name, field, page.url)
    except bitwarden.SecretsError as e:
        return web.json_response({"error": "secrets", "detail": str(e)}, status=400)
    try:
        await el.fill(value, timeout=10000)
    finally:
        value = None
    # The page could change the field while it was filled: check it again,
    # and clear it if it is no longer the kind of field the secret may go in.
    if _field_ok(await el.evaluate(FIELD_JS), field):
        await el.fill("")
        return web.json_response({"error": "secrets", "detail": "the field changed while it was filled; cleared"}, status=400)
    site = urlparse(page.url).hostname or ""
    await asyncio.to_thread(V.agent().report_status, "secret_filled", site, f"{name} ({field})")
    return web.json_response({**await _where(page), "filled": field})


async def login_wall(request):
    page = await V.attach()
    try:
        blocked = bool(await page.evaluate(BLOCKING_JS))
    except Exception:
        blocked = False
    return web.json_response({**await _where(page), "blocked": blocked})


async def _run_takeover(job, reason):
    """Take over through the screen: the agent is disconnected from the browser,
    the owner sees the virtual display on their phone and uses it with taps and
    typing. When they finish, the agent is reconnected."""
    import websockets
    import screen
    page = await V.attach()
    V.used = True
    start_url = job["url"] = page.url
    agent = V.agent()
    site = urlparse(start_url).hostname or ""
    r = await asyncio.to_thread(agent.client.post, f"{agent.base}/api/v1/takeover", json={
        "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(), "url": start_url,
        "reason": reason or "Please take over to continue."})
    if r.status_code != 200:
        raise RuntimeError(f"take over refused: {r.status_code} {r.text[:200]}")
    t = r.json()
    await asyncio.to_thread(agent.report_status, "takeover_started", site, reason[:200])
    ws_url = agent.base.replace("https://", "wss://").replace("http://", "ws://") + \
        f"/api/v1/takeover/{t['takeover_id']}/agent"

    try:
        blocked_at_start = not await login_finished(page)
    except Exception:
        blocked_at_start = False
    cookies_at_start = await _site_session(page.context, _site(site))

    # Disconnect the agent before the owner sees anything.
    await V.detach()
    V.in_takeover = True
    try:
        async with websockets.connect(ws_url, max_size=4_000_000,
                                      additional_headers={"Authorization": "Bearer " + t["agent_token"]}) as ws:
            # wait for the owner to open the viewer (or for the request to end)
            async for raw in ws:
                k = json.loads(raw).get("t")
                if k == "live":
                    break
                if k in ("done", "cancelled", "expired", "agent_left"):
                    return await _after_takeover(job, agent, site, k)
            result = await screen.run(ws, lambda: V.relaunch(start_url), _log,
                                      watcher=lambda w: _watch_signin(w, _site(site), blocked_at_start,
                                                                     cookies_at_start))
    finally:
        V.in_takeover = False
    return await _after_takeover(job, agent, site, result)


async def _after_takeover(job, agent, site, result):
    page = await V.attach()
    job["final"] = page.url
    if result == "done" and not await login_finished(page):
        result = "incomplete"
    await asyncio.to_thread(agent.report_status, f"takeover_{result}", site)
    return result


async def start_takeover(request):
    body = await request.json()
    active = [k for k, j in V.jobs.items() if not j["task"].done()]
    if active:
        return web.json_response({"takeover_id": active[0], "state": "busy"})
    jid = "tk_" + uuid.uuid4().hex[:10]
    job = {"started": time.time(), "url": ""}
    job["task"] = asyncio.create_task(_run_takeover(job, str(body.get("reason", ""))[:200]))
    V.jobs[jid] = job
    return web.json_response({"takeover_id": jid, "state": "started"})


async def wait_takeover(request):
    jid = request.match_info["jid"]
    job = V.jobs.get(jid)
    if not job:
        return web.json_response({"state": "unknown"}, status=404)
    wait = max(1, min(int(request.query.get("wait", 240)), WAIT_MAX))
    done, _ = await asyncio.wait({job["task"]}, timeout=wait)
    secs = int(time.time() - job["started"])
    if not done:
        return web.json_response({"state": "waiting", "after": secs})
    V.jobs.pop(jid, None)
    try:
        result = job["task"].result()
    except Exception as e:
        return web.json_response({"state": "error", "detail": f"{type(e).__name__}: {e}"[:300]})
    return web.json_response({"state": "finished", "result": result, "after": secs,
                              "url": job.get("final") or job["url"]})


async def end_session(request):
    body = await request.json() if request.can_read_body else {}
    report = await V.end_session(str(body.get("why", "agent finished"))[:100])
    return web.json_response({"ended": True, "sign_out": report})


async def on_startup(app):
    app["egress"] = await egress.start()
    await asyncio.to_thread(V.report_crash)
    V.pw = await async_playwright().start()
    await V.wba_refresh()
    await V.start_chrome()
    app["watchdog"] = asyncio.create_task(V.watchdog())


async def on_cleanup(app):
    app["watchdog"].cancel()
    if V.used:
        await V.end_session("vault shutting down")
    await V.stop_chrome()
    await V.pw.stop()


def main():
    app = web.Application(middlewares=[auth])
    app.add_routes([
        web.get("/status", status), web.post("/ping", ping),
        web.post("/navigate", navigate), web.post("/click", click),
        web.post("/type", type_text), web.get("/read", read),
        web.get("/login_wall", login_wall),
        web.get("/secrets", list_secrets), web.post("/fill_secret", fill_secret),
        web.post("/takeover", start_takeover), web.get("/takeover/{jid}", wait_takeover),
        web.post("/end_session", end_session),
        web.post("/press", press), web.post("/select", select), web.post("/scroll", scroll),
        web.post("/back", back), web.post("/wait", wait_for), web.get("/screenshot", screenshot),
    ])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    web.run_app(app, host="0.0.0.0", port=7801, print=None)


if __name__ == "__main__":
    main()
