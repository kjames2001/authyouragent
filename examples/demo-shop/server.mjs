// Demo Shop: a plain website using Auth.js (https://authjs.dev).
// "Sign in with Auth Your Agent" is only configuration: issuer, client id, secret.
import express from "express"
import { ExpressAuth, getSession } from "@auth/express"
import { randomBytes } from "node:crypto"
import { createRemoteJWKSet, jwtVerify } from "jose"

const ISSUER = process.env.AYA_ISSUER || "https://authyouragent.com"
// Sign-ins the provider has ended (owner revoked). A real site would keep
// this in its database; Demo Shop keeps it in memory, and the refresh check
// below catches anything a restart forgets within one access-token lifetime.
const endedSids = new Map()   // sid -> time ended
const JWKS = createRemoteJWKSet(new URL(ISSUER + "/oidc/jwks"))
let meta
async function discover() {
  meta ??= await (await fetch(ISSUER + "/.well-known/openid-configuration")).json()
  return meta.token_endpoint
}

const AYA = {
  id: "authyouragent",
  name: "Auth Your Agent",
  type: "oidc",
  issuer: ISSUER,
  clientId: process.env.AYA_CLIENT_ID,
  clientSecret: process.env.AYA_CLIENT_SECRET,
  authorization: { params: { scope: "openid profile" } },
  profile(p) { return { id: p.sub, name: p.name } },
}

const authConfig = {
  providers: [AYA],
  secret: process.env.AUTH_SECRET,
  trustHost: true,
  callbacks: {
    // Standard Auth.js refresh-token rotation (authjs.dev/guides/refresh-token-rotation),
    // plus one line for back-channel logout: an ended sid ends the session.
    async jwt({ token, profile, account }) {
      if (profile && account) {
        token.owner_sub = profile.sub
        token.agent = profile.act?.name; token.agent_sub = profile.act?.sub
        token.amr = profile.amr; token.auth_time = profile.auth_time
        token.sid = profile.sid
        token.access_token = account.access_token
        token.refresh_token = account.refresh_token
        token.expires_at = account.expires_at
        return token
      }
      if (token.sid && endedSids.has(token.sid)) return null          // owner revoked: signed out
      if (Date.now() < (token.expires_at - 30) * 1000) return token
      const r = await post(await discover(), { grant_type: "refresh_token", refresh_token: token.refresh_token })
      if (!r.ok) return null                                           // revoked or expired: signed out
      const t = await r.json()
      token.access_token = t.access_token
      token.refresh_token = t.refresh_token ?? token.refresh_token
      token.expires_at = Math.floor(Date.now() / 1000) + t.expires_in
      return token
    },
    session({ session, token }) {
      Object.assign(session.user, { agent: token.agent, agent_sub: token.agent_sub, owner_sub: token.owner_sub,
                                    amr: token.amr, auth_time: token.auth_time })
      return session
    },
  },
}

// a form POST to the provider, authenticated with the site's client secret
const post = (url, body) => fetch(url, {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded",
             Authorization: "Basic " + Buffer.from(`${encodeURIComponent(AYA.clientId)}:${encodeURIComponent(AYA.clientSecret)}`).toString("base64") },
  body: new URLSearchParams(body),
})

// ---- Checkout: before charging, the shop asks the agent's OWNER directly
// (OpenID Connect CIBA, poll mode). The agent cannot approve its own purchase;
// the owner's phone shows the shop's own message.
const PRODUCT = { name: "Brass lighthouse lamp", price: "$45.00" }
const orders = new Map()   // id -> order (a real shop: its database)
async function askOwner(o) {
  await discover()
  const r = await post(meta.backchannel_authentication_endpoint, {
    scope: "openid profile", login_hint: o.agent_sub,
    binding_message: `Pay ${PRODUCT.price} for order ${o.id} (${PRODUCT.name})`, requested_expiry: "300" })
  const j = await r.json()
  if (!r.ok) { o.status = "failed"; o.reason = j.error_description || j.error; return }
  Object.assign(o, { auth_req_id: j.auth_req_id, interval: j.interval || 5, next_poll: 0 })
}
async function pollOwner(o) {
  if (o.status !== "pending" || Date.now() < o.next_poll) return
  o.next_poll = Date.now() + o.interval * 1000
  const r = await post(await discover(), { grant_type: "urn:openid:params:grant-type:ciba", auth_req_id: o.auth_req_id })
  const j = await r.json()
  if (j.error === "authorization_pending") return
  if (j.error === "slow_down") { o.interval += 5; return }
  if (j.error) { o.status = j.error === "access_denied" ? "declined" : "expired"; return }
  // the confirmation must come from the same owner, for the same agent
  const { payload } = await jwtVerify(j.id_token, JWKS, { issuer: ISSUER, audience: AYA.clientId })
  if (payload.sub !== o.owner_sub || payload.act?.sub !== o.agent_sub) { o.status = "failed"; o.reason = "wrong person"; return }
  Object.assign(o, { status: "paid", confirmed_at: payload.auth_time, how: (payload.amr || []).filter(x => x !== "agent") })
}

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]))
const page = (body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Demo Shop</title>
<meta name="robots" content="noindex">
<style>body{font:16px/1.55 system-ui,sans-serif;max-width:36rem;margin:8vh auto;padding:0 1.2rem;color:#1f2328}
h1{font-size:1.5rem}.card{border:1px solid #d0d7de;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}
.k{color:#59636e;font-size:.85rem}code{word-break:break-all}button{font:inherit;padding:.6rem 1rem;border-radius:8px;
border:1px solid #0f766e;background:#0f766e;color:#fff;cursor:pointer}.muted{color:#59636e;font-size:.9rem}</style></head>
<body>${body}<p class="muted">A demo website for <a href="https://authyouragent.com">Auth Your Agent</a>.
It uses <a href="https://authjs.dev">Auth.js</a> with no Auth Your Agent code: just an issuer, a client ID and a secret.</p></body></html>`

// shown to site owners: the whole setup of this shop
const OWNERS = `<div class="card"><p><b>Run a website?</b> This is all Demo Shop needed (Auth.js):</p>
<pre style="overflow:auto;font-size:.85rem;background:#f6f8fa;padding:.8rem;border-radius:8px">providers: [{
  id: "authyouragent", name: "Auth Your Agent", type: "oidc",
  issuer: "https://authyouragent.com",
  clientId: process.env.AYA_CLIENT_ID,
  clientSecret: process.env.AYA_CLIENT_SECRET,
}]</pre>
<p class="muted">To end an agent's session the moment its owner revokes it, Demo Shop also
refreshes its tokens and listens at <code>/auth/backchannel-logout</code> (standard OpenID Connect
Back-Channel Logout). About 30 lines.</p>
<p class="muted">Its checkout asks the owner to confirm each payment on their phone, with a standard
OpenID Connect CIBA request (about 40 lines).
<a href="https://authyouragent.com/static/video/demo-shop-checkout.mp4">Watch a recorded checkout</a> (31 s).</p>
<p class="muted">Keycloak, Authentik, WordPress and Django work the same way.
<a href="https://authyouragent.com/docs/developers/sites">Setup guide</a></p></div>`

const app = express()
app.set("trust proxy", true)
app.get("/.well-known/authyouragent-site.txt", (_req, res) => res.type("text/plain").send((process.env.AYA_SITE_VERIFICATION || "") + "\n"))
// OpenID Connect Back-Channel Logout 1.0: the provider POSTs a logout_token
// here when the owner revokes the agent. Verify it, then end that sign-in.
app.post("/auth/backchannel-logout", express.urlencoded({ extended: false, limit: "8kb" }), async (req, res) => {
  res.set("Cache-Control", "no-store")
  try {
    const { payload } = await jwtVerify(String(req.body.logout_token || ""), JWKS, {
      issuer: ISSUER, audience: AYA.clientId, typ: "logout+jwt", maxTokenAge: "5m" })
    if (!payload.events?.["http://schemas.openid.net/event/backchannel-logout"] || payload.nonce || !payload.sid)
      throw new Error("not a logout token")
    endedSids.set(payload.sid, Date.now())
    for (const [k, t] of endedSids) if (Date.now() - t > 31 * 86400e3) endedSids.delete(k)
    console.log("back-channel logout: ended", payload.sid.slice(0, 6) + "...")
    res.sendStatus(200)
  } catch (e) {
    console.log("back-channel logout refused:", e.code || e.message)
    res.status(400).json({ error: "invalid_request" })
  }
})
app.use("/auth/*", ExpressAuth(authConfig))

app.post("/buy", async (req, res) => {
  const s = await getSession(req, authConfig)
  if (!s) return res.redirect(303, "/")
  for (const [k, o] of orders) if (Date.now() - o.created > 3600e3) orders.delete(k)
  if (orders.size > 500) return res.status(503).send(page("<h1>Demo Shop</h1><p>Too many open orders; try again later.</p>"))
  const o = { id: String(1000 + Math.floor(Math.random() * 9000)), key: randomBytes(16).toString("hex"),
              owner_sub: s.user.owner_sub, agent_sub: s.user.agent_sub, agent: s.user.agent,
              status: "pending", created: Date.now() }
  orders.set(o.key, o)
  await askOwner(o)
  res.redirect(303, "/order/" + o.key)
})
const orderOf = async (req) => {
  const s = await getSession(req, authConfig), o = orders.get(req.params.key)
  return s && o && o.owner_sub === s.user.owner_sub ? o : null
}
app.get("/order/:key/status", async (req, res) => {
  const o = await orderOf(req)
  if (!o) return res.status(404).json({ error: "no such order" })
  try { await pollOwner(o) } catch (e) { o.status = "failed"; o.reason = e.message }
  res.set("Cache-Control", "no-store").json({ order: o.id, status: o.status })
})
app.get("/order/:key", async (req, res) => {
  const o = await orderOf(req)
  if (!o) return res.redirect(303, "/")
  try { await pollOwner(o) } catch (e) { o.status = "failed"; o.reason = e.message }
  const when = o.confirmed_at ? new Date(o.confirmed_at * 1000).toISOString().slice(11, 19) + " UTC" : ""
  const body = {
    pending: `<p id="st"><b>Waiting for ${esc(o.agent)}'s owner</b> to confirm on their phone.</p>
      <p class="muted">The shop asked them directly: <i>Pay ${PRODUCT.price} for order ${o.id} (${PRODUCT.name})</i>.
      ${esc(o.agent)} cannot confirm its own purchase.</p>
      <script>setInterval(async()=>{const d=await (await fetch(location.pathname+'/status',{cache:'no-store'})).json();if(d.status!=='pending')location.reload()},3000)</script>`,
    paid: `<p id="st"><b>Paid.</b> The owner confirmed on their phone at ${esc(when)} (${esc((o.how || []).join(", "))}).</p>`,
    declined: `<p id="st"><b>Not paid.</b> The owner declined on their phone.</p>`,
    expired: `<p id="st"><b>Not paid.</b> The owner did not answer in time.</p>`,
    failed: `<p id="st"><b>Not paid.</b> ${esc(o.reason || "The confirmation could not be requested.")}</p>`,
  }[o.status]
  res.send(page(`<h1>Order ${o.id}</h1><div class="card"><p>${esc(PRODUCT.name)}, ${PRODUCT.price}</p>${body}</div>
    <p><a href="/">Back to the shop</a></p>
    <pre id="j" hidden>${esc(JSON.stringify({ order: o.id, status: o.status }))}</pre>`))
})
app.get("/", async (req, res) => {
  const s = await getSession(req, authConfig)
  if (!s) return res.send(page(`<h1>Demo Shop</h1><p>You are not signed in.</p>
    <form method="post" action="/auth/signin/authyouragent"><input type="hidden" name="csrfToken" class="c">
      <button id="aya">Sign in with Auth Your Agent</button></form>
    <form method="post" action="/auth/signin/authyouragent?prompt=login" style="margin-top:.6rem"><input type="hidden" name="csrfToken" class="c">
      <button id="aya-fresh" style="background:#fff;color:#0f766e">Sign in, and ask the owner again</button></form>
    <p class="muted">The first sign-in asks the agent's owner on their phone. Later sign-ins go through
      while that approval stands. The second button asks again every time (<code>prompt=login</code>).</p>
    ${OWNERS}
    <script>fetch('/auth/csrf').then(r=>r.json()).then(d=>document.querySelectorAll('.c').forEach(e=>e.value=d.csrfToken))</script>`))
  const u = s.user, how = (u.amr || []).filter(x => x !== "agent")
  res.send(page(`<h1>Demo Shop</h1><div class="card"><p><b>Signed in: ${esc(u.name)}</b></p>
    <p><span class="k">Agent</span><br>${esc(u.agent)}</p>
    <p><span class="k">How the owner approved</span><br>${esc(how.join(", ") || "-")}${how.includes("grant") ? " (an earlier approval covered it)" : ""}</p>
    <p><span class="k">Owner ID on this site</span><br><code>${esc(u.owner_sub)}</code></p>
    <p><span class="k">Agent ID on this site</span><br><code>${esc(u.agent_sub)}</code></p></div>
    <div class="card"><p><b>${esc(PRODUCT.name)}</b>, ${PRODUCT.price}</p>
    <form method="post" action="/buy"><button id="buy">Buy</button></form>
    <p class="muted">Before charging, the shop asks the agent's owner to confirm on their phone
      (OpenID Connect CIBA). The agent cannot approve its own purchase.</p></div>
    <form method="post" action="/auth/signout"><input type="hidden" name="csrfToken" id="c"><button>Sign out</button></form>
    <script>fetch('/auth/csrf').then(r=>r.json()).then(d=>document.getElementById('c').value=d.csrfToken)</script>
    <pre id="j" hidden>${esc(JSON.stringify({ signed_in: true, user: u }))}</pre>`))
})
app.listen(Number(process.env.PORT || 3999), "0.0.0.0", () => console.log("demo shop up"))
