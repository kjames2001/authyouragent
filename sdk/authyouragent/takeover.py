"""Take over: let the person drive this agent's browser from their phone.

Use it when the agent reaches a wall it must not pass itself: a login,
a CAPTCHA, a 2FA prompt. The person's phone is notified; they see the page
live, tap and type into it, then hand it back.

    from authyouragent import AgentClient
    from authyouragent.takeover import takeover

    result = await takeover(agent, page, "Please sign in to jobs.example.com")
    if result == "done":
        ...  # the page is now signed in; continue

`page` is a Playwright (async API) page on Chromium. Requires the extra
dependency `websockets` (pip install "authyouragent[takeover]").

While the person is in control the function blocks, so the agent does not act
and never reads what the person types beyond what the page itself shows.
Returns "done", "cancelled", "expired", "agent_left" or "incomplete".

Pass `check` (an async function taking the page and returning True when the
job is really finished; `login_finished` covers passwords, one-time codes and
sign-in approvals). While the person is in control the page is watched and
handed back automatically once `check` has passed for 3 seconds in a row. If
they press Done while it is not finished it asks once more (`retries`); if it
is still not finished it returns "incomplete".
"""
import asyncio
import json

try:
    import websockets
except ImportError:  # pragma: no cover
    websockets = None

BLOCKING_JS = r"""() => {
  // Is the page still asking for a password, a one-time code, or a sign-in
  // approval? Reads form fields and visible text only (no screenshots).
  const seen = e => { const r = e.getBoundingClientRect(), cs = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const CODE = /otp|one.?time|2fa|mfa|totp|two.?factor|2.?step|verif|passcode|security.?code|auth.?code|sms.?code|\bpin\b|\bcode\b|token/i;
  const NOT_CODE = /post|zip|promo|coupon|discount|voucher|gift|country|area|referr|invite|search|captcha/i;
  const label = e => [e.name, e.id, e.placeholder, e.getAttribute('aria-label'), e.autocomplete,
    ...[...(e.labels || [])].map(l => l.innerText)].filter(Boolean).join(' ');
  // Pierce shadow DOM — many modern sites (Reddit, Twitter/X, etc.) render
  // login forms inside custom elements, so document.querySelectorAll misses them.
  const allInputs = [];
  (function walk(root) {
    for (const e of root.querySelectorAll('input')) allInputs.push(e);
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  })(document);
  const inputs = allInputs.filter(seen);
  for (const e of inputs) {
    const t = (e.type || 'text').toLowerCase();
    if (t === 'password') return true;
    if ((e.autocomplete || '').includes('one-time-code')) return true;
    if (!['text', 'tel', 'number', ''].includes(t)) continue;
    const l = label(e);
    if (CODE.test(l) && !NOT_CODE.test(l)) return true;
    const ml = e.maxLength;
    if ((e.inputMode === 'numeric' || t === 'tel' || t === 'number') && ml >= 4 && ml <= 8 && !NOT_CODE.test(l)) return true;
  }
  // a row of single-character boxes (one per digit)
  if (inputs.filter(e => e.maxLength === 1).length >= 4) return true;
  // push approval / "check your phone" screens have no field at all
  const text = (document.body && document.body.innerText || '').slice(0, 5000);
  return /approve (the |this |your )?sign.?in|sign.?in request|authenticator app|check your (phone|device)|2.?step verification|two.?step verification|two.?factor|verify (it'?s|it’s) you|enter (the|your) (\d.digit )?(verification |security |sign.?in )?code|we (sent|texted) (a|you a|your) code/i.test(text);
}"""


async def login_finished(page):
    """Text-only check (no screenshots or vision model needed): a login is
    treated as finished when the page no longer asks for a password, a
    one-time code (including rows of digit boxes) or a sign-in approval
    ("approve the sign-in on your phone")."""
    try:
        return not await page.evaluate(BLOCKING_JS)
    except Exception:   # page mid-navigation: not finished yet
        return False


# Describes the focused form field so the phone can put a real text box over
# it (a single box across a row of one-digit boxes). Password values are never
# read.
FOCUS_JS = r"""() => {
  // Descend into shadow DOM: document.activeElement returns the shadow host,
  // not the input inside it. Walk down to the real focused element.
  let e = document.activeElement;
  while (e && e.shadowRoot && e.shadowRoot.activeElement) e = e.shadowRoot.activeElement;
  if (!e || !e.matches('input, textarea, [contenteditable=""], [contenteditable="true"]')) return null;
  const k = (e.type || (e.tagName === 'TEXTAREA' ? 'textarea' : 'text')).toLowerCase();
  if (['checkbox','radio','button','submit','file','range','color','hidden','image','reset'].includes(k)) return null;
  // Clean up previous overlay markers (search shadow roots too)
  (function walk(root) {
    root.querySelectorAll('[data-aya-box]').forEach(b => b.removeAttribute('data-aya-box'));
    for (const el of root.querySelectorAll('*')) if (el.shadowRoot) walk(el.shadowRoot);
  })(document);
  const fs = parseFloat(getComputedStyle(e).fontSize) || 16;
  // a row of single-digit boxes: one text box across the whole row
  if (e.tagName === 'INPUT' && e.maxLength === 1) {
    const root = e.closest('form') || e.parentElement.parentElement || document.body;
    const boxes = [...root.querySelectorAll('input')].filter(b => b.maxLength === 1 &&
      b.getBoundingClientRect().width > 0);
    if (boxes.length >= 4) {
      boxes.forEach((b, i) => b.setAttribute('data-aya-box', String(i)));
      const rs = boxes.map(b => b.getBoundingClientRect());
      const x = Math.min(...rs.map(r => r.x)), y = Math.min(...rs.map(r => r.y));
      return {x, y, w: Math.max(...rs.map(r => r.right)) - x, h: Math.max(...rs.map(r => r.bottom)) - y,
              kind: 'boxes', fs, numeric: true, maxlen: boxes.length, multiline: false,
              value: boxes.map(b => b.value).join('')};
    }
  }
  try { e.setSelectionRange(e.value.length, e.value.length); } catch (_) {}
  const r = e.getBoundingClientRect();
  const l = [e.name, e.id, e.placeholder, e.getAttribute('aria-label'), e.autocomplete,
             ...[...(e.labels || [])].map(x => x.innerText)].filter(Boolean).join(' ');
  const numeric = e.inputMode === 'numeric' || k === 'tel' || k === 'number' ||
    (/otp|one.?time|2fa|mfa|totp|verif|passcode|\bcode\b|\bpin\b/i.test(l) && !/post|zip|promo|coupon/i.test(l));
  return {x: r.x, y: r.y, w: r.width, h: r.height, kind: k, fs, numeric,
          maxlen: e.maxLength > 0 ? e.maxLength : 0,
          multiline: e.tagName === 'TEXTAREA' || e.isContentEditable,
          value: k === 'password' ? '' : String(e.value ?? e.textContent ?? '').slice(0, 500)};
}"""


SETTLE_S = 3.0

KEYS = {"Enter", "Backspace", "Tab", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"}


async def takeover(agent, page, reason, on_live=None, quality=60, verify=True,
                   phone_size=(412, 760), check=None, retries=1,
                   retry_reason="That doesn't look finished yet. Please complete it "
                                "(for example, press the page's Sign in button), then tap Done.",
                   clear_session=False):
    """Ask the owner to take over `page`; optionally verify the result.

    If ``clear_session`` is true, after the owner finishes and the check
    passes, the page's cookies, localStorage and sessionStorage are cleared
    so the agent cannot reuse the owner's login session afterwards. The
    owner's credentials and session tokens never leave the owner's typing;
    this only clears what the browser stored during the takeover."""
    for attempt in range(retries + 1):
        result = await _takeover_once(agent, page, reason if attempt == 0 else retry_reason,
                                      on_live, quality, verify, phone_size, check)
        if result != "done" or check is None:
            return result
        await asyncio.sleep(0.5)
        if await check(page):
            if clear_session:
                await _clear_session(page)
            return "done"
    if clear_session and result == "incomplete":
        await _clear_session(page)
    return "incomplete"


async def _clear_session(page):
    """Clear cookies, localStorage and sessionStorage so the agent cannot
    reuse the owner's login session after the takeover ends."""
    try:
        await page.context.clear_cookies()
    except Exception:
        pass
    try:
        await page.evaluate("() => { try { localStorage.clear(); } catch(e) {} "
                            "try { sessionStorage.clear(); } catch(e) {} }")
    except Exception:
        pass


async def _takeover_once(agent, page, reason, on_live, quality, verify, phone_size, check=None):
    """Ask the owner to take over `page`. Blocks until they finish.

    While the person is in control the page is shown at phone size
    (`phone_size`, None to keep the agent's own size) and restored after."""
    if websockets is None:
        raise RuntimeError('pip install websockets (or "authyouragent[takeover]")')
    r = await asyncio.to_thread(agent.client.post, f"{agent.base}/api/v1/takeover", json={
        "agent_id": agent.agent_id, "agent_jwt": agent._agent_jwt(),
        "url": page.url, "reason": reason})
    if r.status_code != 200:
        from .agent import AgentError
        raise AgentError(f"takeover refused: {r.status_code} {r.text}")
    t = r.json()
    ws_url = agent.base.replace("https://", "wss://").replace("http://", "ws://") + \
        f"/api/v1/takeover/{t['takeover_id']}/agent"
    ws_kw = {}   # websockets >= 14 refuses an explicit ssl=None for wss://
    if ws_url.startswith("wss://") and not verify:   # local test servers only
        import ssl
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        ws_kw["ssl"] = ssl_ctx
    cdp = await page.context.new_cdp_session(page)
    own_vp = page.viewport_size
    emulated = False
    if phone_size and own_vp:
        await page.set_viewport_size({"width": phone_size[0], "height": phone_size[1]})
    elif phone_size:   # a browser we attached to over CDP: emulate, then clear
        await cdp.send("Emulation.setDeviceMetricsOverride", {
            "width": phone_size[0], "height": phone_size[1], "deviceScaleFactor": 0, "mobile": False})
        emulated = True
    vp = page.viewport_size or ({"width": phone_size[0], "height": phone_size[1]} if phone_size
                                else {"width": 1280, "height": 800})
    # auto handback: only when something was blocking at the start and later is gone
    blocked_at_start = check is not None and not await check(page)
    async with websockets.connect(ws_url, max_size=4_000_000, **ws_kw,
                                  additional_headers={"Authorization": "Bearer " + t["agent_token"]}) as ws:
        async def on_frame(ev):
            try:
                await cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]})
                m = ev["metadata"]
                await ws.send(json.dumps({"t": "frame", "data": ev["data"],
                                          "w": m["deviceWidth"], "h": m["deviceHeight"]}))
            except Exception:
                pass
        cdp.on("Page.screencastFrame", lambda ev: asyncio.ensure_future(on_frame(ev)))
        await cdp.send("Page.startScreencast", {"format": "jpeg", "quality": quality,
                                                "maxWidth": vp["width"], "maxHeight": vp["height"],
                                                "everyNthFrame": 1})
        async def send_url(url):
            try:
                await ws.send(json.dumps({"t": "url", "url": url}))
            except Exception:
                pass

        def on_nav(f):
            if f == page.main_frame:
                asyncio.ensure_future(send_url(f.url))
        page.on("framenavigated", on_nav)
        async def send_focus():
            try:
                field = await page.evaluate(FOCUS_JS)
            except Exception:
                field = None
            await ws.send(json.dumps({"t": "focus", "field": field}))

        # While the person is in control, watch the page (text only, once a
        # second): when the blocking step is gone (e.g. signed in), hand back
        # automatically. Only when something was blocking at the start.
        pending = {"task": None}

        async def watch():
            # finished for SETTLE_S in a row: a 2FA step that appears a moment
            # after the password is caught before handing back
            ok_since = None
            while True:
                await asyncio.sleep(0.5)
                try:
                    ok = await check(page)
                except Exception:
                    ok = False                            # mid-navigation: not yet
                now = asyncio.get_running_loop().time()
                if not ok:
                    ok_since = None
                elif ok_since is None:
                    ok_since = now
                elif now - ok_since >= SETTLE_S:
                    await ws.send(json.dumps({"t": "done"}))
                    return

        def start_watch():
            if blocked_at_start and not pending["task"]:
                pending["task"] = asyncio.ensure_future(watch())

        result = "agent_left"
        try:
            async for raw in ws:
                m = json.loads(raw)
                k = m.get("t")
                if k == "live":
                    start_watch()
                    if on_live:
                        on_live()
                elif k == "click":
                    await page.mouse.click(float(m["x"]), float(m["y"]))
                    await asyncio.sleep(0.15)
                    await send_focus()
                elif k == "set":
                    v = str(m.get("value", ""))[:1000]
                    boxes = page.locator("[data-aya-box]")
                    n = await boxes.count()
                    if n:
                        # one character per box, typed with real key events
                        for i in range(n):
                            box = page.locator(f'[data-aya-box="{i}"]')
                            await box.focus()
                            await page.keyboard.press("Control+A")
                            if i < len(v):
                                await page.keyboard.type(v[i])
                            else:
                                await page.keyboard.press("Backspace")
                        await page.locator(f'[data-aya-box="{min(len(v), n - 1)}"]').focus()
                    else:
                        await page.keyboard.press("Control+A")
                        if v:
                            await page.keyboard.type(v)
                        else:
                            await page.keyboard.press("Backspace")
                elif k == "text":
                    await page.keyboard.type(str(m.get("text", ""))[:500])
                elif k == "key" and m.get("key") in KEYS:
                    await page.keyboard.press(m["key"])
                    if m["key"] == "Tab":
                        await send_focus()
                elif k == "scroll":
                    await page.mouse.wheel(0, float(m.get("dy", 0)))
                    await ws.send(json.dumps({"t": "focus", "field": None}))
                elif k in ("done", "cancelled", "expired", "agent_left"):
                    result = k
                    break
        finally:
            page.remove_listener("framenavigated", on_nav)
            if pending["task"] and not pending["task"].done():
                pending["task"].cancel()
            try:
                await cdp.send("Page.stopScreencast")
                if emulated:
                    await cdp.send("Emulation.clearDeviceMetricsOverride")
                await cdp.detach()
            except Exception:
                pass
            if phone_size and own_vp:
                try:
                    await page.set_viewport_size(own_vp)
                except Exception:
                    pass
    return result
