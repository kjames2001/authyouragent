// Auth Your Agent SDK for JavaScript and TypeScript.
//
// Zero dependencies. Uses the Web Crypto API and fetch, so it runs on
// Node.js 18+, Deno, Bun and edge runtimes (Cloudflare Workers, Vercel Edge).
//
//   import { AgentClient, SiteVerifier } from "authyouragent";
//
// Docs: https://authyouragent.com/docs/developers/quickstart

export const DEFAULT_CLOUD = "https://authyouragent.com";
export const VERSION = "0.2.0";

const subtle = globalThis.crypto && globalThis.crypto.subtle;
if (!subtle) throw new Error("authyouragent: Web Crypto (crypto.subtle) is not available in this runtime");

const enc = new TextEncoder();
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const SIGN = { name: "ECDSA", hash: "SHA-256" };

// ------------------------------------------------------------------ helpers
function b64url(bytes) {
  let s = "";
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
}
const b64json = (o) => b64url(enc.encode(JSON.stringify(o)));
const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function randomId(n = 12) {
  return b64url(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}
async function sha256b64(text) {
  return b64url(await subtle.digest("SHA-256", enc.encode(text)));
}
function pemToDer(pem) {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return b64urlDecode(body.replace(/\+/g, "-").replace(/\//g, "_"));
}
function derToPem(der, label) {
  const b = btoa(String.fromCharCode(...new Uint8Array(der)));
  return `-----BEGIN ${label}-----\n${b.match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;
}
async function signJws(privateKey, header, payload) {
  const input = b64json(header) + "." + b64json(payload);
  // Web Crypto ECDSA signatures are already raw r||s (the JWS encoding)
  const sig = await subtle.sign(SIGN, privateKey, enc.encode(input));
  return input + "." + b64url(sig);
}
function decodeJwtPart(tok, i) {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(tok.split(".")[i])));
}
// RFC 7638 thumbprint of an EC P-256 JWK
async function jwkThumbprint(jwk) {
  const canon = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return sha256b64(canon);
}
function normUrl(u) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)(.*)$/.exec(String(u || "").trim());
  if (!m) return String(u || "");
  const scheme = m[1].toLowerCase();
  let host = m[2].toLowerCase();
  if (scheme === "https" && host.endsWith(":443")) host = host.slice(0, -4);
  if (scheme === "http" && host.endsWith(":80")) host = host.slice(0, -3);
  return `${scheme}://${host}${m[3]}`;
}
function hostOf(url) {
  return new URL(url).hostname;
}
function errorDetail(body) {
  if (!body || typeof body !== "object") return "";
  if (typeof body.detail === "string") return body.detail;
  if (body.detail && typeof body.detail === "object") return body.detail.error || JSON.stringify(body.detail);
  return body.error || "";
}

// ------------------------------------------------------------------ errors
export class AgentError extends Error {
  constructor(message, { status, code } = {}) {
    super(message);
    this.name = "AgentError";
    this.status = status;
    this.code = code;
  }
}
export class AuthError extends Error {
  constructor(error) {
    super(error);
    this.name = "AuthError";
    this.error = error;
  }
}

// ------------------------------------------------------------------ keys
/** Generate an agent key pair locally. The private key never leaves this process
 *  unless you export it. Returns { privateKeyPem, publicKeyPem, jwk }. */
export async function keygen() {
  const kp = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
  const pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await subtle.exportKey("spki", kp.publicKey);
  const j = await subtle.exportKey("jwk", kp.publicKey);
  return {
    privateKeyPem: derToPem(pkcs8, "PRIVATE KEY"),
    publicKeyPem: derToPem(spki, "PUBLIC KEY"),
    jwk: { kty: "EC", crv: "P-256", x: j.x, y: j.y },
  };
}

async function importPrivateKey(pem) {
  const key = await subtle.importKey("pkcs8", pemToDer(pem), ECDSA, true, ["sign"]);
  const j = await subtle.exportKey("jwk", key);
  return { key, jwk: { kty: "EC", crv: "P-256", x: j.x, y: j.y } };
}

// ================================================================== agent
/**
 * The agent side: ask a person for access, then call sites with a
 * short-lived pass and a fresh DPoP proof on every request.
 */
export class AgentClient {
  /**
   * @param {object} o
   * @param {string} o.agentId        the agent id from the app (ag_…)
   * @param {string} o.privateKeyPem  PKCS#8 PEM (from keygen or `python -m authyouragent keygen`)
   * @param {string} [o.baseUrl]      Auth Your Agent cloud (default https://authyouragent.com)
   * @param {number} [o.pollInterval] ms between approval checks (default 1500)
   * @param {number} [o.approvalTimeout] ms to wait for the person (default 330000)
   * @param {typeof fetch} [o.fetch]  custom fetch
   */
  constructor({ agentId, privateKeyPem, baseUrl = DEFAULT_CLOUD, pollInterval = 1500,
                approvalTimeout = 330000, fetch: f } = {}) {
    if (!agentId || !privateKeyPem) throw new AgentError("agentId and privateKeyPem are required");
    this.agentId = agentId;
    this.base = baseUrl.replace(/\/+$/, "");
    this.pollInterval = pollInterval;
    this.approvalTimeout = approvalTimeout;
    this._fetch = f || globalThis.fetch.bind(globalThis);
    this._keyP = importPrivateKey(privateKeyPem);
    this._access = new Map();   // site -> { token, exp }
    this._refresh = new Map();  // site -> refresh token
    this._inflight = new Map(); // site -> Promise<token>
  }

  async _agentJwt(ttl = 300) {
    const { key } = await this._keyP;
    const t = now();
    return signJws(key, { alg: "ES256", typ: "JWT" },
      { iss: this.agentId, sub: this.agentId, iat: t, exp: t + ttl, type: "agent" });
  }

  /** A DPoP proof (RFC 9449) for one request. */
  async dpopProof(method, url, accessToken) {
    const { key, jwk } = await this._keyP;
    const payload = { htm: method.toUpperCase(), htu: url, url, iat: now(), jti: "j_" + randomId(9) };
    if (accessToken) payload.ath = await sha256b64(accessToken);
    return signJws(key, { typ: "dpop+jwt", alg: "ES256", jwk }, payload);
  }

  async _post(path, body, headers = {}) {
    let r;
    try {
      r = await this._fetch(this.base + path, {
        method: "POST", headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new AgentError(`cloud unreachable: ${e.message || e}`);
    }
    const data = await r.json().catch(() => ({}));
    return { status: r.status, data };
  }

  async _waitFor(txnId, { stepup = false } = {}) {
    const deadline = Date.now() + this.approvalTimeout;
    while (Date.now() < deadline) {
      let r;
      try {
        r = await this._fetch(`${this.base}/api/v1/authz-requests/${encodeURIComponent(txnId)}`, {
          headers: { "x-agent-jwt": await this._agentJwt() } });
      } catch (_) { await sleep(this.pollInterval); continue; }
      if (r.status >= 500) { await sleep(this.pollInterval); continue; }
      if (r.status === 404) throw new AgentError("the approval request no longer exists", { status: 404 });
      const d = await r.json().catch(() => ({}));
      if (d.status === "approved" && (!stepup || d.stepup_token)) return d;
      if (d.status === "denied" || d.status === "expired")
        throw new AgentError(`approval ${d.status} by user`, { code: d.status });
      await sleep(this.pollInterval);
    }
    throw new AgentError("approval timed out", { code: "timeout" });
  }

  /**
   * Ask for access to `site`. Resolves true once approved (or if it already was).
   * @param {string} site
   * @param {string[]} scopes
   * @param {{wait?: boolean, userInfo?: string[]}} [opts]
   */
  async ensureGrant(site, scopes, { wait = true, userInfo } = {}) {
    const body = { agent_id: this.agentId, site, scopes, agent_jwt: await this._agentJwt() };
    if (userInfo) body.user_info = userInfo;
    const r = await this._post("/api/v1/authz-requests", body);
    if (r.status === 409) return true;
    if (r.status === 403) {
      const d = errorDetail(r.data);
      if (/revoked/i.test(d)) throw new AgentError(`agent revoked by owner: ${d}`, { status: 403, code: "revoked" });
      await this._token(site);
      return true;
    }
    if (r.status >= 400) throw new AgentError(`access request failed: ${r.status} ${errorDetail(r.data)}`, { status: r.status });
    if (!wait) return null;
    await this._waitFor(r.data.txn_id);
    this._access.delete(site);
    await this._token(site);
    return true;
  }

  async _token(site) {
    const cur = this._access.get(site);
    if (cur && cur.exp > Date.now() / 1000 + 30) return cur.token;
    if (this._inflight.has(site)) return this._inflight.get(site);
    const p = (async () => {
      const refresh = this._refresh.get(site);
      const body = { agent_id: this.agentId, site, agent_jwt: await this._agentJwt() };
      let r = await this._post("/api/v1/token", refresh ? { ...body, refresh_token: refresh } : body);
      if (r.status === 401 && refresh) {           // rotated away: re-enter once
        this._refresh.delete(site);
        r = await this._post("/api/v1/token", { ...body, agent_jwt: await this._agentJwt() });
      }
      if (r.status === 403) throw new AgentError("no grant — call ensureGrant() first", { status: 403, code: "no_grant" });
      if (r.status >= 400) throw new AgentError(`token request failed: ${r.status} ${errorDetail(r.data)}`, { status: r.status });
      const exp = Date.now() / 1000 + Number(r.data.expires_in || 0);
      this._access.set(site, { token: r.data.access_token, exp });
      if (r.data.refresh_token) this._refresh.set(site, r.data.refresh_token);
      return r.data.access_token;
    })();
    this._inflight.set(site, p);
    try { return await p; } finally { this._inflight.delete(site); }
  }

  async _stepup(site, action) {
    const r = await this._post("/api/v1/stepup",
      { agent_id: this.agentId, site, action, agent_jwt: await this._agentJwt() });
    if (r.status >= 400) return null;
    try { return (await this._waitFor(r.data.txn_id, { stepup: true })).stepup_token; }
    catch (_) { return null; }
  }

  /**
   * Call a site on the person's behalf. Returns the fetch Response.
   * With `stepupAction`, a 403 {error:"stepup_required"} asks the person
   * again and retries once. `site` is the site id you were granted; it
   * defaults to the URL's host.
   * @param {string} url
   * @param {RequestInit & {stepupAction?: string, site?: string}} [init]
   */
  async fetch(url, init = {}) {
    const { stepupAction, site: siteId, ...req } = init;
    const method = (req.method || "GET").toUpperCase();
    const site = siteId || hostOf(url);
    const send = async (extra = {}) => {
      const at = await this._token(site);
      const headers = new Headers(req.headers || {});
      headers.set("authorization", `Bearer ${at}`);
      headers.set("dpop", await this.dpopProof(method, url, at));
      for (const [k, v] of Object.entries(extra)) headers.set(k, v);
      return this._fetch(url, { ...req, method, headers });
    };
    const res = await send();
    if (res.status !== 403 || !stepupAction) return res;
    const body = await res.clone().json().catch(() => null);
    const err = body && (body.error || (body.detail && body.detail.error));
    if (err !== "stepup_required") return res;
    const st = await this._stepup(site, stepupAction);
    if (!st) return res;
    return send({ "x-authyouragent-stepup": st });
  }
}

// ================================================================== site
function header(req, name) {
  const h = req.headers;
  if (!h) return "";
  if (typeof h.get === "function") return h.get(name) || "";
  const v = h[name] ?? h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : (v || "");
}

/**
 * The site side: check that a request really comes from an agent a person
 * approved. Works with the Fetch API Request (Workers, Next.js, Deno, Bun)
 * and Node/Express requests (pass `url` explicitly or set publicBaseUrl).
 */
export class SiteVerifier {
  /**
   * @param {object} [o]
   * @param {string} [o.baseUrl]           Auth Your Agent cloud
   * @param {string} [o.expectedAudience]  your site id (normally your hostname)
   * @param {string} [o.publicBaseUrl]     public origin agents call, e.g. https://jobs.example.com
   * @param {"cloud"|"local"} [o.mode]     cloud (default) or local verification
   * @param {number} [o.revTtl]            local mode: seconds a revocation list is trusted (60)
   * @param {number} [o.maxStale]          local mode: max age of a list when refresh fails (5*revTtl)
   * @param {typeof fetch} [o.fetch]
   */
  constructor({ baseUrl = DEFAULT_CLOUD, expectedAudience, publicBaseUrl, mode = "cloud",
                revTtl = 60, maxStale, fetch: f } = {}) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.issuer = this.base;
    this.expectedAudience = expectedAudience;
    this.publicBaseUrl = publicBaseUrl ? publicBaseUrl.replace(/\/+$/, "") : undefined;
    this.mode = mode;
    this.revTtl = revTtl;
    this.maxStale = maxStale ?? 5 * revTtl;
    this._fetch = f || globalThis.fetch.bind(globalThis);
    this._jwks = null; this._jwksAt = 0;
    this._rev = null; this._revAt = 0;
    this._seen = new Map();
  }

  /** The absolute URL the agent signed. */
  expectedUrl(req, url) {
    const raw = url || req.url || "";
    let path = raw;
    if (/^https?:\/\//i.test(raw)) {
      if (!this.publicBaseUrl) return raw.split("#")[0].split("?")[0];
      path = new URL(raw).pathname;
    } else path = (raw.split("?")[0] || "/");
    if (this.publicBaseUrl) {
      const pb = new URL(this.publicBaseUrl);
      const bpath = pb.pathname.replace(/\/+$/, "");
      if (bpath && !(path === bpath || path.startsWith(bpath + "/"))) path = bpath + path;
      return pb.origin + path;
    }
    const host = header(req, "host");
    if (!host) throw new AuthError("cannot determine request URL; set publicBaseUrl");
    return `https://${host}${path}`;
  }

  /**
   * Verify a request. Resolves to
   * { agentId, agentName, userId, site, scopes, userInfo, stepup } or throws AuthError.
   * @param {Request|object} req
   * @param {{url?: string, action?: string}} [opts]
   */
  async verify(req, { url, action } = {}) {
    const auth = header(req, "authorization");
    const at = /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, "").trim() : "";
    const dpop = header(req, "dpop");
    if (!at || !dpop) throw new AuthError("missing Bearer/DPoP credentials");
    const method = (req.method || "GET").toUpperCase();
    const target = this.expectedUrl(req, url);
    const stepup = header(req, "x-authyouragent-stepup");
    return this.mode === "local"
      ? this._verifyLocal(at, dpop, method, target, stepup, action)
      : this._verifyCloud(at, dpop, method, target, stepup, action);
  }

  async _verifyCloud(at, dpop, method, url, stepup, action) {
    const body = { access_token: at, dpop, method, url };
    if (stepup) body.stepup_token = stepup;
    if (this.expectedAudience) body.site = this.expectedAudience;
    if (action) body.action = action;
    let r;
    try {
      r = await this._fetch(this.base + "/api/v1/verify", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    } catch (e) { throw new AuthError(`cloud unreachable: ${e.message || e}`); }
    if (r.status !== 200) throw new AuthError(`cloud unreachable: ${r.status}`);
    const d = await r.json().catch(() => null);
    if (!d || d.valid !== true) throw new AuthError((d && d.error) || "verification failed");
    if (this.expectedAudience && d.site !== this.expectedAudience) throw new AuthError("audience mismatch");
    return { agentId: d.agent_id, agentName: d.agent_name, userId: d.user_id, site: d.site,
             scopes: d.scopes || [], userInfo: d.user_info || {}, stepup: !!d.stepup };
  }

  async _getJson(path) {
    const r = await this._fetch(this.base + path);
    if (r.status !== 200) throw new AuthError(`cloud unreachable: ${r.status}`);
    return r.json();
  }
  async _keys(force = false) {
    if (this._jwks && !force && Date.now() - this._jwksAt < 3600e3) return this._jwks;
    try {
      const d = await this._getJson("/api/v1/jwks");
      const m = new Map();
      for (const k of d.keys) m.set(k.kid, await subtle.importKey("jwk",
        { kty: k.kty, crv: k.crv, x: k.x, y: k.y }, ECDSA, false, ["verify"]));
      this._jwks = m; this._jwksAt = Date.now();
    } catch (e) {
      if (!this._jwks || force) throw e instanceof AuthError ? e : new AuthError(`JWKS: ${e.message || e}`);
    }
    return this._jwks;
  }
  async _verifyJwt(tok, { force = false } = {}) {
    const parts = String(tok).split(".");
    if (parts.length !== 3) throw new AuthError("token malformed");
    const [h, p, s] = parts;
    let hdr;
    try { hdr = decodeJwtPart(tok, 0); } catch (_) { throw new AuthError("token malformed"); }
    if (hdr.alg !== "ES256") throw new AuthError("unsupported token alg");
    let key = (await this._keys(force)).get(hdr.kid);
    if (!key && !force) key = (await this._keys(true)).get(hdr.kid);
    if (!key) throw new AuthError("unknown signing key");
    const ok = await subtle.verify(SIGN, key, b64urlDecode(s), enc.encode(h + "." + p));
    if (!ok) throw new AuthError("token signature invalid");
    let c;
    try { c = decodeJwtPart(tok, 1); } catch (_) { throw new AuthError("token malformed"); }
    if (c.iss !== this.issuer) throw new AuthError("bad issuer");
    return c;
  }
  async _revocation() {
    if (this._rev && Date.now() - this._revAt < this.revTtl * 1000) return this._rev;
    try {
      const d = await this._getJson("/api/v1/revocation");
      const c = await this._verifyJwt(d.signature, { force: !this._rev });
      if (c.type !== "revocation" || c.rev_seq !== d.rev_seq) throw new AuthError("revocation list invalid");
      this._rev = {
        iat: c.iat,
        agents: new Map((c.revoked_agents || []).map((a) => [a.id, a.flag])),
        grants: new Set((c.revoked_grants || []).map((g) => g.agent + "\n" + g.site)),
      };
      this._revAt = Date.now();
    } catch (e) {
      if (!this._rev) throw e instanceof AuthError ? e : new AuthError(`revocation list unavailable: ${e.message || e}`);
      if (now() - this._rev.iat > this.maxStale) throw new AuthError("revocation list too stale");
    }
    return this._rev;
  }

  async _verifyLocal(at, dpop, method, url, stepup, action) {
    const c = await this._verifyJwt(at);
    if (c.exp <= now()) throw new AuthError("access token expired");
    if ((c.type || "access") !== "access") throw new AuthError("not an access token");
    const aud = c.aud;
    if (this.expectedAudience ? aud !== this.expectedAudience : aud !== new URL(url).hostname)
      throw new AuthError("audience mismatch");
    // DPoP
    let ph, pc;
    try { ph = decodeJwtPart(dpop, 0); pc = decodeJwtPart(dpop, 1); }
    catch (_) { throw new AuthError("DPoP: malformed proof"); }
    if (ph.typ !== "dpop+jwt" || ph.alg !== "ES256") throw new AuthError("DPoP: bad header");
    if (!ph.jwk || ph.jwk.kty !== "EC" || ph.jwk.crv !== "P-256") throw new AuthError("DPoP: jwk must be EC P-256");
    if (pc.htm !== method) throw new AuthError("DPoP: htm mismatch");
    if (normUrl(pc.htu ?? pc.url) !== normUrl(url)) throw new AuthError("DPoP: url mismatch");
    if (typeof pc.iat !== "number" || Math.abs(now() - pc.iat) > 120) throw new AuthError("DPoP: iat stale");
    if (typeof pc.jti !== "string" || pc.jti.length < 8) throw new AuthError("DPoP: jti missing");
    if (pc.ath !== await sha256b64(at)) throw new AuthError("DPoP: ath mismatch");
    const [h, p, s] = dpop.split(".");
    const pub = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: ph.jwk.x, y: ph.jwk.y }, ECDSA, false, ["verify"]);
    let sig = b64urlDecode(s);
    if (sig.length !== 64) throw new AuthError("DPoP: signature must be raw r||s");
    if (!(await subtle.verify(SIGN, pub, sig, enc.encode(h + "." + p)))) throw new AuthError("DPoP: signature invalid");
    const jkt = await jwkThumbprint(ph.jwk);
    if (!c.cnf || c.cnf.dpop !== jkt) throw new AuthError("DPoP key != cnf-bound key");
    const key = jkt + "\n" + pc.jti;
    const t = Date.now();
    if (this._seen.size > 50000) for (const [k, e] of this._seen) if (e <= t) this._seen.delete(k);
    if ((this._seen.get(key) || 0) > t) throw new AuthError("DPoP: proof replayed");
    this._seen.set(key, t + 130e3);
    // revocation
    const rev = await this._revocation();
    const flag = rev.agents.get(c.sub);
    if (flag && flag !== "ok") throw new AuthError(`agent ${c.sub} globally ${flag}`);
    if (rev.grants.has(c.sub + "\n" + aud)) throw new AuthError("grant for site revoked");
    // step-up: always confirmed with the cloud (single use)
    let stepupOk = false;
    if (stepup) {
      const sc = await this._verifyJwt(stepup);
      if (sc.type !== "stepup" || sc.sub !== c.sub || sc.aud !== aud) throw new AuthError("step-up: token mismatch");
      const body = { stepup_token: stepup, site: aud };
      if (action) body.action = action;
      let r;
      try {
        r = await this._fetch(this.base + "/api/v1/stepup/verify", {
          method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      } catch (e) { throw new AuthError(`cloud unreachable: ${e.message || e}`); }
      const d = await r.json().catch(() => null);
      if (!d || d.valid !== true) throw new AuthError(`step-up: ${(d && d.error) || "used or expired"}`);
      stepupOk = true;
    }
    return { agentId: c.sub, agentName: undefined, userId: c.user, site: aud,
             scopes: c.scope || [], userInfo: c.user_info || {}, stepup: stepupOk };
  }
}
