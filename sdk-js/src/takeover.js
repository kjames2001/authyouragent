// Take over: let the person drive this agent's browser from their phone.
//
//   import { AgentClient } from "authyouragent";
//   import { takeover, loginFinished } from "authyouragent/takeover";
//   const result = await takeover(agent, page, "Please sign in to jobs.example.com",
//                                 { check: loginFinished });
//
// `page` is a Playwright page on Chromium. Needs the `ws` package
// (npm i ws); the core SDK stays dependency-free.
//
// While the person is in control this call waits, so the agent does not act.
// With `check`, the page is watched (text only, no vision model) and handed
// back automatically once the blocking step is gone, e.g. after Sign in.
// Resolves "done" | "cancelled" | "expired" | "agent_left" | "incomplete".

const KEYS = new Set(["Enter", "Backspace", "Tab", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"]);

const BLOCKING_JS = String.raw`(() => {
  // Is the page still asking for a password, a one-time code, or a sign-in
  // approval? Reads form fields and visible text only (no screenshots).
  const seen = e => { const r = e.getBoundingClientRect(), cs = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const CODE = /otp|one.?time|2fa|mfa|totp|two.?factor|2.?step|verif|passcode|security.?code|auth.?code|sms.?code|\bpin\b|\bcode\b|token/i;
  const NOT_CODE = /post|zip|promo|coupon|discount|voucher|gift|country|area|referr|invite|search|captcha/i;
  const label = e => [e.name, e.id, e.placeholder, e.getAttribute('aria-label'), e.autocomplete,
    ...[...(e.labels || [])].map(l => l.innerText)].filter(Boolean).join(' ');
  const inputs = [...document.querySelectorAll('input')].filter(seen);
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
})()`;

// Describes the focused field so the phone can lay a real text box over it
// (one box across a row of one-digit boxes). Password values are never read.
const FOCUS_JS = String.raw`(() => {
  const e = document.activeElement;
  if (!e || !e.matches('input, textarea, [contenteditable=""], [contenteditable="true"]')) return null;
  const k = (e.type || (e.tagName === 'TEXTAREA' ? 'textarea' : 'text')).toLowerCase();
  if (['checkbox','radio','button','submit','file','range','color','hidden','image','reset'].includes(k)) return null;
  document.querySelectorAll('[data-aya-box]').forEach(b => b.removeAttribute('data-aya-box'));
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
})()`;

const SETTLE_MS = 3000;

/** Text-only check: true when the page no longer asks for a password, a
 *  one-time code (including rows of digit boxes) or a sign-in approval. */
export async function loginFinished(page) {
  try { return !(await page.evaluate(BLOCKING_JS)); } catch { return false; }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Ask the owner to take over `page`; resolves when they are finished. */
export async function takeover(agent, page, reason, {
  check = null, retries = 1, phoneSize = [412, 760], quality = 60, onLive = null,
  insecure = false, clearSession = false,
  retryReason = "That doesn't look finished yet. Please complete it (for example, press the page's Sign in button), then tap Done.",
} = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const result = await once(agent, page, attempt ? retryReason : reason,
                              { check, phoneSize, quality, onLive, insecure });
    if (result !== "done" || !check) {
      if (clearSession && result === "incomplete") await clearBrowserSession(page);
      return result;
    }
    await sleep(500);
    if (await check(page)) {
      if (clearSession) await clearBrowserSession(page);
      return "done";
    }
  }
  if (clearSession) await clearBrowserSession(page);
  return "incomplete";
}

async function clearBrowserSession(page) {
  try { await page.context().clearCookies(); } catch (e) {}
  try { await page.evaluate(() => { try { localStorage.clear(); } catch(e) {} try { sessionStorage.clear(); } catch(e) {} }); } catch (e) {}
}

async function once(agent, page, reason, { check, phoneSize, quality, onLive, insecure }) {
  let WebSocket;
  try { ({ default: WebSocket } = await import("ws")); }
  catch { throw new Error('takeover needs the "ws" package: npm i ws'); }

  const { status, data } = await agent._post("/api/v1/takeover", {
    agent_id: agent.agentId, agent_jwt: await agent._agentJwt(), url: page.url(), reason,
  });
  if (status !== 200) throw new Error(`takeover refused: ${status} ${JSON.stringify(data)}`);

  const cdp = await page.context().newCDPSession(page);
  const ownVp = page.viewportSize();
  let emulated = false;
  if (phoneSize && ownVp) await page.setViewportSize({ width: phoneSize[0], height: phoneSize[1] });
  else if (phoneSize) {
    await cdp.send("Emulation.setDeviceMetricsOverride",
      { width: phoneSize[0], height: phoneSize[1], deviceScaleFactor: 0, mobile: false });
    emulated = true;
  }
  const vp = page.viewportSize() || { width: phoneSize?.[0] || 1280, height: phoneSize?.[1] || 800 };
  const blockedAtStart = !!check && !(await check(page));

  const wsUrl = agent.base.replace(/^http/, "ws") + `/api/v1/takeover/${data.takeover_id}/agent`;
  const ws = new WebSocket(wsUrl, { headers: { authorization: "Bearer " + data.agent_token },
                                    rejectUnauthorized: !insecure, maxPayload: 4_000_000 });
  await new Promise((ok, fail) => { ws.once("open", ok); ws.once("error", fail); });
  const send = (m) => { try { ws.send(JSON.stringify(m)); } catch { /* closed */ } };

  cdp.on("Page.screencastFrame", async (ev) => {
    try {
      await cdp.send("Page.screencastFrameAck", { sessionId: ev.sessionId });
      send({ t: "frame", data: ev.data, w: ev.metadata.deviceWidth, h: ev.metadata.deviceHeight });
    } catch { /* page gone */ }
  });
  await cdp.send("Page.startScreencast", { format: "jpeg", quality, maxWidth: vp.width, maxHeight: vp.height });
  const onNav = (f) => { if (f === page.mainFrame()) send({ t: "url", url: f.url() }); };
  page.on("framenavigated", onNav);

  const sendFocus = async () => {
    let field = null;
    try { field = await page.evaluate(FOCUS_JS); } catch { /* navigating */ }
    send({ t: "focus", field });
  };

  let watching = false, stopped = false;
  // finished for SETTLE_MS in a row, so a 2FA step that appears a moment
  // after the password is caught before handing back
  const watch = async () => {
    let okSince = null;
    while (!stopped) {
      await sleep(500);
      let ok = false;
      try { ok = await check(page); } catch { /* mid-navigation */ }
      if (!ok) okSince = null;
      else if (okSince === null) okSince = Date.now();
      else if (Date.now() - okSince >= SETTLE_MS) { send({ t: "done" }); return; }
    }
  };

  // one message at a time, in order
  let chain = Promise.resolve();
  const result = await new Promise((resolve) => {
    // a result message may still be queued in `chain` when the socket closes
    ws.on("close", () => { chain.then(() => resolve("agent_left")); });
    ws.on("message", (raw) => { chain = chain.then(async () => {
      const m = JSON.parse(raw.toString());
      switch (m.t) {
        case "live":
          if (blockedAtStart && !watching) { watching = true; watch(); }
          onLive?.();
          break;
        case "click":
          await page.mouse.click(+m.x, +m.y); await sleep(150); await sendFocus(); break;
        case "set": {
          const v = String(m.value || "").slice(0, 1000);
          const n = await page.locator("[data-aya-box]").count();
          if (n) {   // one character per digit box, with real key events
            for (let i = 0; i < n; i++) {
              await page.locator(`[data-aya-box="${i}"]`).focus();
              await page.keyboard.press("Control+A");
              if (i < v.length) await page.keyboard.type(v[i]); else await page.keyboard.press("Backspace");
            }
            await page.locator(`[data-aya-box="${Math.min(v.length, n - 1)}"]`).focus();
          } else {
            await page.keyboard.press("Control+A");
            if (v) await page.keyboard.type(v); else await page.keyboard.press("Backspace");
          }
          break;
        }
        case "text": await page.keyboard.type(String(m.text || "").slice(0, 500)); break;
        case "key":
          if (KEYS.has(m.key)) { await page.keyboard.press(m.key); if (m.key === "Tab") await sendFocus(); }
          break;
        case "scroll": await page.mouse.wheel(0, +m.dy || 0); send({ t: "focus", field: null }); break;
        case "done": case "cancelled": case "expired": case "agent_left": resolve(m.t); break;
      }
    }).catch(() => {}); });
  });

  stopped = true;
  page.off("framenavigated", onNav);
  try {
    await cdp.send("Page.stopScreencast");
    if (emulated) await cdp.send("Emulation.clearDeviceMetricsOverride");
    await cdp.detach();
  } catch { /* already gone */ }
  if (phoneSize && ownVp) { try { await page.setViewportSize(ownVp); } catch { /* closed */ } }
  try { ws.close(); } catch { /* closed */ }
  return result;
}
