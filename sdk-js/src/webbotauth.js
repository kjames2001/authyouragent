// Web Bot Auth: sign requests as an agent, and check any agent's signature
// (draft-ietf-webbotauth-httpsig-protocol-00 on HTTP Message Signatures,
// RFC 9421). JavaScript port of the Python SDK's `authyouragent.webbotauth`;
// same outcomes, same limits. No dependencies: Web Crypto, plus Node's own
// dns/tls/zlib for the key-list fetch.
//
//     import { verify } from "authyouragent/webbotauth";
//     const result = await verify(request);      // Fetch Request, Node/Express req, or {method, url, headers}
//     if (result.verified) console.log(result.agent);   // the URL the keys came from
//
// Outcomes (draft Appendix C.1): "verified", "invalid" (signature, covered
// parts, key or times are wrong), "unverified" (not enough to decide, e.g. the
// key list cannot be fetched or lacks the key), "unsigned".
import { b64Encode, b64uEncode, b64uDecode } from "./_b64.js";
import { SFError, parseDictionary, parseItem, serItem, serMember } from "./_sfv.js";

export const TAG = "web-bot-auth";
export const DIRECTORY_TAG = "http-message-signatures-directory";
export const WELL_KNOWN = "/.well-known/http-message-signatures-directory";
export const MEDIA_TYPE = "application/http-message-signatures-directory+json";
export const REQUEST_LIFETIME = 300;
export const DIRECTORY_LIFETIME = 3600;
export const VERIFIED = "verified", INVALID = "invalid", UNVERIFIED = "unverified", UNSIGNED = "unsigned";

// Thumbprints of the RFC 9421 Appendix B.1 example keys. Draft 6.8: refuse them.
export const TEST_KEYS = new Set([
  "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", // test-key-ed25519
  "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", // test-key-rsa-pss
  "BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo", // test-key-rsa
  "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI", // test-key-ecc-p256
]);

const UA = "authyouragent-webbotauth (+https://authyouragent.com/docs/developers/web-bot-auth)";
// Node 18 has no global crypto in ES modules; node:crypto's webcrypto is the same API.
const webcrypto = globalThis.crypto && globalThis.crypto.subtle ? globalThis.crypto
  : (await import("node:crypto")).webcrypto;
const subtle = webcrypto.subtle;
const te = new TextEncoder();
const utf8 = (s) => te.encode(s);

class Invalid extends Error {}
export class Unverified extends Error {}

async function sha(alg, bytes) { return new Uint8Array(await subtle.digest(alg, bytes)); }

/** RFC 7638 thumbprint (Ed25519, EC, RSA): the Web Bot Auth keyid. */
export async function thumbprint(jwk) {
  const canon = jwk.kty === "RSA" ? { e: jwk.e, kty: "RSA", n: jwk.n }
    : jwk.kty === "EC" ? { crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return b64uEncode(await sha("SHA-256", utf8(JSON.stringify(canon))));
}

// ── URLs ──
// Split an absolute URL without normalising it: @path/@query must be the
// bytes the client sent, and WHATWG URL would re-encode them.
function urlParts(url) {
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?/.exec(String(url));
  if (!m) throw new Unverified("not an absolute URL");
  let auth = m[2], userinfo = false;
  const at = auth.lastIndexOf("@");
  if (at >= 0) { userinfo = true; auth = auth.slice(at + 1); }
  const hm = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(auth);
  if (!hm) throw new Unverified("bad authority");
  let port = null;
  if (hm[2] !== undefined && hm[2] !== "") {
    port = Number(hm[2]);
    if (!(port >= 0 && port <= 65535)) throw new Unverified("bad port");
  }
  return { scheme: m[1].toLowerCase(), host: hm[1].replace(/^\[|\]$/g, "").toLowerCase(), port,
           path: m[3], query: m[4] ?? "", hasQuery: m[4] !== undefined, userinfo };
}

/** RFC 9421 @authority: lower-case host, port only when not the default. */
export function authority(url) {
  const u = urlParts(url);
  let host = u.host.includes(":") ? `[${u.host}]` : u.host;
  if (u.port && !((u.scheme === "https" && u.port === 443) || (u.scheme === "http" && u.port === 80))) host += `:${u.port}`;
  return host;
}

// ── keys and signing (the agent side) ──
/** A new Ed25519 key pair (Web Crypto CryptoKeyPair). */
export async function newKey() { return subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]); }
/** {kty, crv, x} for a key pair or public key. */
export async function publicJwk(key) {
  const j = await subtle.exportKey("jwk", key.publicKey || key);
  return { kty: "OKP", crv: "Ed25519", x: j.x };
}

function params(components, created, expires, keyid, tag, nonce) {
  let out = `(${components.join(" ")});created=${created};keyid="${keyid}";alg="ed25519";expires=${expires}`;
  if (nonce) out += `;nonce="${nonce}"`;
  return out + `;tag="${tag}"`;
}

/** Headers to add to one request. Covers authority, method, path and Signature-Agent. */
export async function signRequest(key, method, url, signatureAgent, { now, lifetime = REQUEST_LIFETIME } = {}) {
  now = Math.floor(now ?? Date.now() / 1000);
  const u = urlParts(url);
  const agent = `"${signatureAgent}"`;
  const nonce = b64Encode(webcrypto.getRandomValues(new Uint8Array(64)));
  const p = params(['"@authority"', '"@method"', '"@path"', '"signature-agent"'], now, now + lifetime,
    await thumbprint(await publicJwk(key)), TAG, nonce);
  const base = [`"@authority": ${authority(url)}`, `"@method": ${String(method).toUpperCase()}`,
    `"@path": ${u.path || "/"}`, `"signature-agent": ${agent}`, `"@signature-params": ${p}`].join("\n");
  const sig = new Uint8Array(await subtle.sign({ name: "Ed25519" }, key.privateKey || key, utf8(base)));
  return { "Signature-Agent": agent, "Signature-Input": `sig1=${p}`, "Signature": `sig1=:${b64Encode(sig)}:` };
}

/** Exact bytes of a one-key directory. */
export async function directoryBody(jwk) {
  const entry = { kty: jwk.kty, crv: jwk.crv, kid: await thumbprint(jwk), x: jwk.x, use: "sig" };
  return utf8(JSON.stringify({ keys: [entry] }));
}

/** Possession proof for a directory response (draft Appendix B), bound to `host`. */
export async function signDirectory(key, body, host, { now, lifetime = DIRECTORY_LIFETIME } = {}) {
  now = Math.floor(now ?? Date.now() / 1000);
  const digest = "sha-256=:" + b64Encode(await sha("SHA-256", body)) + ":";
  const p = params(['"@authority";req', '"content-digest"'], now, now + lifetime, await thumbprint(await publicJwk(key)), DIRECTORY_TAG);
  const base = [`"@authority";req: ${host}`, `"content-digest": ${digest}`, `"@signature-params": ${p}`].join("\n");
  const sig = new Uint8Array(await subtle.sign({ name: "Ed25519" }, key.privateKey || key, utf8(base)));
  return { "Content-Digest": digest, "Signature-Input": `binding=${p}`, "Signature": `binding=:${b64Encode(sig)}:` };
}

// ── the request being checked ──
function headerLists(headers) {
  const out = {};
  if (headers == null) return out;
  let pairs;
  if (typeof headers.entries === "function" && !Array.isArray(headers)) pairs = [...headers.entries()];
  else if (Array.isArray(headers)) {
    // [[k, v], ...] or Node rawHeaders [k, v, k, v]
    pairs = Array.isArray(headers[0]) ? headers : headers.flatMap((x, i) => (i % 2 ? [] : [[x, headers[i + 1]]]));
  } else pairs = Object.entries(headers);
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    const lk = String(k).toLowerCase();
    for (const one of Array.isArray(v) ? v : [v]) (out[lk] ||= []).push(String(one));
  }
  return out;
}

const ABS = /^[a-z][a-z0-9+.-]*:\/\//i;

// (method, url as the client sent it, headers) from a request object.
// Fetch Requests carry an absolute URL; Node/Express ones carry the raw
// request target, so the origin comes from publicBaseUrl or the Host header.
function fromRequest(req, publicBaseUrl) {
  let url = req.originalUrl || req.url || "";   // Express mounts rewrite req.url
  if (!url) throw new Unverified("cannot determine request URL");
  if (!ABS.test(url)) {
    let origin;
    if (publicBaseUrl) origin = publicBaseUrl.replace(/\/+$/, "");
    else {
      const h = headerLists(req.headers);
      const host = h.host && h.host[0];
      if (!host) throw new Unverified("cannot determine request URL; pass publicBaseUrl");
      origin = `${req.socket && req.socket.encrypted ? "https" : "http"}://${host}`;
    }
    url = origin + (url.startsWith("/") ? "" : "/") + url;
  }
  return [req.method, url, req.headers];
}

// WHATWG x-www-form-urlencoded byte serialiser, %20 for space (RFC 9421 2.2.8).
function formEncode(s) {
  let out = "";
  for (const b of utf8(s)) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9*\-._]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}
// Python's parse_qsl(keep_blank_values=True): split on "&", "+" is a space,
// then percent escapes decode as UTF-8.
function parseQuery(q) {
  if (!q) return [];
  const dec = (s) => {
    s = s.replace(/\+/g, " ");
    try { return decodeURIComponent(s); } catch { return s.replace(/%([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); }
  };
  return q.split("&").filter(Boolean).map((p) => {
    const i = p.indexOf("=");
    return i < 0 ? [dec(p), ""] : [dec(p.slice(0, i)), dec(p.slice(i + 1))];
  });
}

class Msg {
  constructor(method, url, headers) {
    this.method = String(method || "GET");
    this.url = String(url);
    this.u = urlParts(this.url);
    this.h = headerLists(headers);
  }
  field(name) {
    const vals = this.h[name];
    return vals === undefined ? null : vals.map((v) => v.replace(/^[ \t]+|[ \t]+$/g, "")).join(", ");
  }
  component(name, p) {
    if (name.startsWith("@")) {
      const extra = Object.keys(p).filter((k) => !(name === "@query-param" && k === "name"));
      if (extra.length) throw new Unverified(`component parameter ${extra} on ${name} not supported`);
      const u = this.u;
      switch (name) {
        case "@method": return this.method;
        case "@target-uri": return this.url;
        case "@authority": return authority(this.url);
        case "@scheme": return u.scheme;
        case "@path": return u.path || "/";
        case "@query": return "?" + u.query;
        case "@request-target": return (u.path || "/") + (u.query ? "?" + u.query : "");
        case "@query-param": {
          const want = p.name;
          if (!want || want.t !== "str") throw new Invalid("@query-param needs a name");
          const hits = parseQuery(u.query).filter(([k]) => formEncode(k) === want.v);
          if (hits.length !== 1) throw new Invalid(`query parameter ${JSON.stringify(want.v)} ${hits.length ? "repeated" : "missing"}`);
          return formEncode(hits[0][1]);
        }
      }
      throw new Unverified(`component ${name} not supported`);
    }
    const extra = Object.keys(p).filter((k) => k !== "key");
    if (extra.length) throw new Unverified(`component parameter ${extra} on ${name} not supported`);
    const raw = this.field(name);
    if (raw === null) throw new Invalid(`covered header ${name} is missing`);
    if (p.key) {
      let d;
      try { d = parseDictionary(raw); } catch (e) { throw new Invalid(`header ${name} is not a dictionary: ${e.message}`); }
      if (!Object.hasOwn(d, p.key.v)) throw new Invalid(`header ${name} has no member ${JSON.stringify(p.key.v)}`);
      return serMember(d[p.key.v]);
    }
    return raw;
  }
  // covered: [[{t:"str", v:name}, params], ...] as parsed from Signature-Input
  base(covered, member) {
    const lines = [];
    for (const [item, p] of covered) {
      if (item.t !== "str" || item.v !== item.v.toLowerCase()) throw new Invalid("component names must be lower-case strings");
      const val = this.component(item.v, p);
      if (/[\r\n]/.test(val)) throw new Invalid(`component ${item.v} contains a line break`);
      lines.push(`${serItem(item, p)}: ${val}`);
    }
    lines.push(`"@signature-params": ${serMember(member)}`);
    return utf8(lines.join("\n"));
  }
}

// ── keys from a key list ──
function bitLength(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  return i === bytes.length ? 0 : (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}

async function loadJwk(jwk) {
  if (!jwk || typeof jwk !== "object" || ["d", "p", "q", "k"].some((k) => k in jwk)) return null;
  try {
    if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
      if (typeof jwk.x !== "string" || b64uDecode(jwk.x).length !== 32) return null;
      const pub = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
      return [await thumbprint(jwk), pub, "ed25519"];
    }
    if (jwk.kty === "EC" && (jwk.crv === "P-256" || jwk.crv === "P-384")) {
      const pub = await subtle.importKey("jwk", { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: jwk.crv }, false, ["verify"]);
      return [await thumbprint(jwk), pub, jwk.crv];
    }
    if (jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string") {
      if (bitLength(b64uDecode(jwk.n)) < 2048) return null;
      const j = { kty: "RSA", n: jwk.n, e: jwk.e };
      const pss = await subtle.importKey("jwk", j, { name: "RSA-PSS", hash: "SHA-512" }, false, ["verify"]);
      const v15 = await subtle.importKey("jwk", j, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      return [await thumbprint(jwk), { pss, v15 }, "RSA:" + String(jwk.alg || "")];
    }
  } catch { return null; }
  return null;
}

const ALG_FOR = { ed25519: ["ed25519"], "P-256": ["ecdsa-p256-sha256"], "P-384": ["ecdsa-p384-sha384"] };

async function checkSig(pub, kind, algItem, sig, base) {
  if (algItem && algItem.t !== "str") throw new Invalid("alg must be a string");
  let alg = algItem ? algItem.v : null;
  if (alg === "hmac-sha256") throw new Invalid("shared-secret signatures are not allowed (draft 6.4)");
  if (kind.startsWith("RSA:")) {
    alg = alg || { PS512: "rsa-pss-sha512", RS256: "rsa-v1_5-sha256" }[kind.slice(4)];
    if (alg !== "rsa-pss-sha512" && alg !== "rsa-v1_5-sha256") throw new Invalid("RSA signature without a usable alg");
  } else {
    const ok = ALG_FOR[kind];
    alg = alg || ok[0];
    if (!ok.includes(alg)) throw new Invalid(`alg ${alg} does not match the ${kind} key`);
  }
  let good = false;
  try {
    if (alg === "ed25519") good = await subtle.verify({ name: "Ed25519" }, pub, sig, base);
    else if (alg === "rsa-pss-sha512") good = await subtle.verify({ name: "RSA-PSS", saltLength: 64 }, pub.pss, sig, base);
    else if (alg === "rsa-v1_5-sha256") good = await subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, pub.v15, sig, base);
    else {
      const n = alg === "ecdsa-p256-sha256" ? 32 : 48;   // raw r||s, which is what Web Crypto takes
      good = sig.length === 2 * n && await subtle.verify({ name: "ECDSA", hash: n === 32 ? "SHA-256" : "SHA-384" }, pub, sig, base);
    }
  } catch { good = false; }
  if (!good) throw new Invalid("signature does not verify");
  return alg;
}

// ── which addresses may be fetched (draft 6.7) ──
function v4(ip) {
  const p = ip.split(".");
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || +x > 255)) return null;
  return p.map(Number);
}
function v6(ip) {
  let s = ip.toLowerCase().split("%")[0];
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const a = v4(tail[1]);
    if (!a) return null;
    s = s.slice(0, -tail[1].length) + ((a[0] << 8) | a[1]).toString(16) + ":" + ((a[2] << 8) | a[3]).toString(16);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const part = (h) => (h ? h.split(":") : []);
  const a = part(halves[0]), b = halves.length === 2 ? part(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - a.length - b.length : 0;
  if (fill < 0 || (halves.length === 1 && a.length !== 8)) return null;
  const g = [...a, ...Array(fill).fill("0"), ...b];
  if (g.length !== 8 || g.some((x) => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return g.map((x) => parseInt(x, 16));
}
function publicV4(a) {
  const [w, x, y] = a;
  return !(w === 0 || w === 10 || w === 127 || w >= 224 ||
    (w === 100 && x >= 64 && x <= 127) || (w === 169 && x === 254) || (w === 172 && x >= 16 && x <= 31) ||
    (w === 192 && x === 168) || (w === 192 && x === 0 && (y === 0 || y === 2)) || (w === 192 && x === 88 && y === 99) ||
    (w === 198 && (x === 18 || x === 19)) || (w === 198 && x === 51 && y === 100) || (w === 203 && x === 0 && y === 113));
}
/** True for a globally routable address (not private, loopback, link-local, CGNAT, ULA, multicast, documentation). */
export function isPublicAddress(ip) {
  if (!ip.includes(":")) { const a = v4(ip); return !!a && publicV4(a); }
  const g = v6(ip);
  if (!g) return false;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return publicV4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255]);
  if (g.slice(0, 6).every((x) => x === 0)) return false;          // ::, ::1, IPv4-compatible
  if (g[0] === 0x64 && g[1] === 0xff9b) return false;             // NAT64
  if ((g[0] & 0xe000) !== 0x2000) return false;                   // only 2000::/3 is global unicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false;           // documentation
  if (g[0] === 0x2001 && g[1] < 0x0200) return false;             // 2001::/23 special purpose (Teredo, ORCHID...)
  if (g[0] === 0x2002) return false;                              // 6to4 (embeds an IPv4 address)
  return true;
}

// ── fetching a key list ──
let _node = null;
async function nodeMods() {
  if (_node !== null) return _node;
  try {
    const [dns, tls, zlib] = await Promise.all([import("node:dns"), import("node:tls"), import("node:zlib")]);
    _node = { dns: dns.promises, tls, zlib };
  } catch { _node = false; }
  return _node;
}

/**
 * GET one https URL with the draft's SSRF limits: a wall-clock timeout, a size
 * cap after decoding, no redirects (a 3xx is returned as is) and, in Node,
 * public addresses only; the connection goes to the address that was checked,
 * so DNS rebinding cannot swap it. Resolves [status, {header: value}, Uint8Array].
 * `ca` adds trusted certificates (tests).
 */
export async function httpsGet(url, { timeout = 5, maxBytes = 65536, allowPrivate = false, accept = MEDIA_TYPE, ca } = {}) {
  const u = urlParts(url);
  if (u.scheme !== "https" || !u.host) throw new Unverified("key list must be fetched over https");
  const deadline = Date.now() + timeout * 1000;
  const N = await nodeMods();
  if (!N) return fetchGet(url, { deadline, maxBytes, accept });
  let addrs;
  try { addrs = (await N.dns.lookup(u.host, { all: true, verbatim: true })).map((a) => a.address); }
  catch (e) { throw new Unverified(`cannot resolve ${u.host}: ${e.code || e.message}`); }
  const usable = allowPrivate ? addrs : addrs.filter(isPublicAddress);
  if (!usable.length) throw new Unverified(`${u.host} resolves only to non-public addresses`);
  const port = u.port || 443;
  const path = (u.path || "/") + (u.hasQuery ? "?" + u.query : "");
  let last = "no address";
  for (const ip of usable.slice(0, 3)) {
    if (Date.now() >= deadline) break;
    try {
      return await rawGet(N, { ip, port, servername: u.host, ca, path, hostHeader: authority(url), accept, maxBytes, deadline });
    } catch (e) {
      if (e instanceof Unverified) throw e;
      last = e.code || e.message;
    }
  }
  if (Date.now() >= deadline) throw new Unverified("key list fetch timed out");
  throw new Unverified(`cannot connect to ${u.host}: ${last}`);
}

function rawGet(N, { ip, port, servername, ca, path, hostHeader, accept, maxBytes, deadline }) {
  return new Promise((resolve, reject) => {
    let settled = false, connected = false;
    const isIp = /^[\d.]+$/.test(servername) || servername.includes(":");
    const opts = { host: ip, port, ALPNProtocols: ["http/1.1"],
      checkServerIdentity: (_h, cert) => N.tls.checkServerIdentity(servername, cert) };
    if (!isIp) opts.servername = servername;
    if (ca) opts.ca = [...N.tls.rootCertificates, ca];
    const sock = N.tls.connect(opts);
    const finish = (err, val) => {
      if (settled) return;
      settled = true; clearTimeout(timer); sock.destroy();
      err ? reject(err) : resolve(val);
    };
    // a hard deadline: a server that trickles bytes defeats per-read timeouts
    const timer = setTimeout(() => finish(connected ? new Unverified("key list fetch timed out")
      : Object.assign(new Error("connect timeout"), { code: "ETIMEDOUT" })), Math.max(0, deadline - Date.now()));
    let head = Buffer.alloc(0), headers = null, status = 0;
    let decoder = null, comp = [], compLen = 0, out = [], outLen = 0, rawLeft = -1, chunked = false, chunkBuf = Buffer.alloc(0);
    const tooBig = () => finish(new Unverified(`key list larger than ${maxBytes} bytes`));
    const onBody = (buf) => {
      if (!buf.length) return true;
      if (decoder) {
        comp.push(buf); compLen += buf.length;
        if (compLen > maxBytes) { tooBig(); return false; }   // compressed bytes are capped too
        return true;
      }
      out.push(buf); outLen += buf.length;
      if (outLen > maxBytes) { tooBig(); return false; }
      return true;
    };
    const complete = () => {
      let body = Buffer.concat(out);
      if (decoder) {
        try {
          // maxOutputLength stops a gzip bomb while inflating
          body = N.zlib[decoder](Buffer.concat(comp), { maxOutputLength: maxBytes + 1 });
        } catch (e) {
          if (e.code === "ERR_BUFFER_TOO_LARGE" || e instanceof RangeError) return tooBig();
          return finish(new Unverified("key list could not be decompressed"));
        }
        if (body.length > maxBytes) return tooBig();
      }
      finish(null, [status, headers, new Uint8Array(body)]);
    };
    const onChunked = (buf) => {
      chunkBuf = Buffer.concat([chunkBuf, buf]);
      for (;;) {
        const nl = chunkBuf.indexOf("\r\n");
        if (nl < 0) return;
        const size = parseInt(chunkBuf.slice(0, nl).toString("latin1").split(";")[0].trim(), 16);
        if (!Number.isFinite(size)) return finish(new Unverified("bad chunked encoding"));
        if (size === 0) return complete();
        if (chunkBuf.length < nl + 2 + size + 2) return;
        if (!onBody(chunkBuf.slice(nl + 2, nl + 2 + size))) return;
        chunkBuf = chunkBuf.slice(nl + 2 + size + 2);
      }
    };
    sock.once("secureConnect", () => {
      connected = true;
      sock.write(`GET ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\nAccept: ${accept}\r\nAccept-Encoding: identity\r\n` +
        `User-Agent: ${UA}\r\nConnection: close\r\n\r\n`);
    });
    sock.on("data", (c) => {
      if (settled) return;
      if (!headers) {
        head = Buffer.concat([head, c]);
        const i = head.indexOf("\r\n\r\n");
        if (i < 0) { if (head.length > 32768) finish(new Unverified("key list headers too large")); return; }
        const lines = head.slice(0, i).toString("latin1").split("\r\n");
        const sm = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0]);
        if (!sm) return finish(new Unverified("not an HTTP/1.1 response"));
        status = +sm[1];
        headers = {};
        for (const l of lines.slice(1)) {
          const k = l.indexOf(":");
          if (k > 0) {
            const name = l.slice(0, k).trim().toLowerCase(), v = l.slice(k + 1).trim();
            headers[name] = name in headers ? headers[name] + ", " + v : v;
          }
        }
        const enc = (headers["content-encoding"] || "identity").trim().toLowerCase();
        if (enc === "gzip" || enc === "x-gzip") decoder = "gunzipSync";
        else if (enc === "deflate") decoder = "inflateSync";
        else if (enc !== "identity" && enc !== "") return finish(new Unverified(`key list sent with unsupported content-encoding ${enc}`));
        chunked = /chunked/i.test(headers["transfer-encoding"] || "");
        if (!chunked && headers["content-length"] !== undefined) {
          rawLeft = parseInt(headers["content-length"], 10);
          if (!(rawLeft >= 0)) return finish(new Unverified("bad content-length"));
          if (rawLeft > maxBytes) return tooBig();
        }
        c = head.slice(i + 4);
        if (status === 204 || status === 304 || (status >= 100 && status < 200) || rawLeft === 0) return complete();
      }
      if (chunked) return onChunked(c);
      if (rawLeft >= 0) {
        const take = c.slice(0, rawLeft);
        rawLeft -= take.length;
        if (onBody(take) && rawLeft === 0) complete();
        return;
      }
      onBody(c);
    });
    sock.on("end", () => {
      if (settled) return;
      if (!headers) return finish(new Unverified("connection closed before the answer"));
      if (chunked || rawLeft > 0) return finish(new Unverified("key list answer cut short"));
      complete();
    });
    sock.on("error", (e) => {
      if (settled) return;
      if (!connected && /CERT|SELF_SIGNED|UNABLE_TO|ERR_TLS|SSL|altnames|certificate/i.test(`${e.code} ${e.message}`))
        return finish(new Unverified(`TLS to ${servername} failed: ${e.code || e.message}`));
      finish(e);
    });
  });
}

// Browsers and edge runtimes without node:dns. They cannot reach a private
// address from a public page; the size and time limits are applied here.
async function fetchGet(url, { deadline, maxBytes, accept }) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), Math.max(0, deadline - Date.now()));
  try {
    const res = await fetch(url, { headers: { accept }, redirect: "manual", signal: ctrl.signal });
    const hdrs = {};
    res.headers.forEach((v, k) => { hdrs[k] = v; });
    const reader = res.body && res.body.getReader();
    const parts = [];
    let n = 0;
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > maxBytes) { ctrl.abort(); throw new Unverified(`key list larger than ${maxBytes} bytes`); }
      parts.push(value);
    }
    const body = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { body.set(p, o); o += p.length; }
    return [res.type === "opaqueredirect" ? 302 : res.status, hdrs, body];
  } catch (e) {
    if (e instanceof Unverified) throw e;
    if (e.name === "AbortError") throw new Unverified("key list fetch timed out");
    throw new Unverified(`fetching the key list failed: ${e.name}`);
  } finally { clearTimeout(t); }
}

// ── key lists ──
function originOf(u) {
  const host = u.host.includes(":") ? `[${u.host}]` : u.host;
  return `https://${host}` + (u.port && u.port !== 443 ? `:${u.port}` : "");
}
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;
// RFC 3986 6.2.2: upper-case percent escapes, decode unreserved, drop dot segments.
function normPath(p) {
  let out = "";
  for (let i = 0; i < p.length;) {
    if (p[i] === "%" && /^[0-9a-fA-F]{2}$/.test(p.slice(i + 1, i + 3))) {
      const ch = String.fromCharCode(parseInt(p.slice(i + 1, i + 3), 16));
      out += UNRESERVED.test(ch) ? ch : p.slice(i, i + 3).toUpperCase();
      i += 3;
    } else out += p[i++];
  }
  const segs = [];
  for (const s of out.split("/")) {
    if (s === "..") { if (segs.length > 1) segs.pop(); }
    else if (s !== ".") segs.push(s);
  }
  return segs.join("/") || "/";
}

/** [identifier, fetch URL] for one Signature-Agent member (draft 5.5). */
export function identifier(value, type = "directory") {
  let u;
  try { u = urlParts(value); }
  catch (e) { throw new Unverified(e.message === "bad port" ? "Signature-Agent has a bad port" : "Signature-Agent must be an https URL"); }
  if (u.scheme !== "https" || !u.host || u.userinfo) throw new Unverified("Signature-Agent must be an https URL");
  if (type === "directory") {
    if ((u.path !== "" && u.path !== "/") || u.hasQuery || value.includes("#"))
      throw new Unverified("a directory Signature-Agent must be an origin (scheme and host only)");
    const url = originOf(u) + WELL_KNOWN;
    return [url, url];
  }
  if (type === "jwks_uri") return [originOf(u) + normPath(u.path || "/"), value];
  throw new Unverified(`Signature-Agent type ${JSON.stringify(type)} not supported`);
}

/** Seconds a key list may be reused, from Cache-Control / Expires / Age. */
export function ttl(hdrs, def, cap) {
  const cc = {};
  for (const part of String(hdrs["cache-control"] || "").split(",")) {
    const i = part.indexOf("=");
    const k = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
    if (k) cc[k] = i < 0 ? "" : part.slice(i + 1).trim().replace(/^"|"$/g, "");
  }
  if ("no-store" in cc || "no-cache" in cc) return 0;
  let t = null;
  if (/^\d+$/.test(cc["max-age"] ?? "")) t = +cc["max-age"];
  else if (hdrs.expires) {
    const exp = Date.parse(hdrs.expires), date = hdrs.date ? Date.parse(hdrs.date) : Date.now();
    t = Number.isFinite(exp) && Number.isFinite(date) ? Math.max(0, Math.floor((exp - date) / 1000)) : 0;
  }
  if (t === null) t = def;
  if (/^\d+$/.test(hdrs.age || "")) t -= +hdrs.age;
  return Math.max(0, Math.min(t, cap));
}

const seconds = (v) => (typeof v !== "number" || !Number.isFinite(v) ? null : v > 1e11 ? v / 1000 : v);  // Cloudflare's demo writes ms

async function digestOk(field, body) {
  let d;
  try { d = parseDictionary(field); } catch { return false; }
  const algs = { "sha-256": "SHA-256", "sha-512": "SHA-512" };
  let seen = false;
  for (const [name, [val]] of Object.entries(d)) {
    if (!algs[name]) continue;
    if (val.t !== "bytes") return false;
    const got = await sha(algs[name], body);
    if (got.length !== val.v.length || got.some((b, i) => b !== val.v[i])) return false;
    seen = true;
  }
  return seen;
}

/** Parse one key-list response. Exported for tests. */
export async function parseList(status, hdrs, body, type, host, now, maxKeys = 32) {
  if (status !== 200) throw new Unverified(`key list answered HTTP ${status}`);
  const ctype = String(hdrs["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (type === "directory" && ctype !== MEDIA_TYPE) throw new Unverified(`key list served as ${ctype || "no content-type"}, not ${MEDIA_TYPE}`);
  let doc;
  try { doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)); } catch { throw new Unverified("key list is not JSON"); }
  const keys = doc && typeof doc === "object" && !Array.isArray(doc) ? doc.keys : null;
  if (!Array.isArray(keys)) throw new Unverified("key list has no keys array");
  if (keys.length > maxKeys) throw new Unverified(`key list holds more than ${maxKeys} keys`);
  const kl = { keys: new Map(), testKeys: new Set(), proof: new Set(), fetched: 0, freshUntil: 0 };
  for (const jwk of keys) {
    const got = await loadJwk(jwk);
    if (!got) continue;
    const [thumb, pub, kind] = got;
    if (type === "directory" && "kid" in jwk && jwk.kid !== thumb) continue;   // draft 5.5: kid is the thumbprint
    const nbf = seconds(jwk.nbf), exp = seconds(jwk.exp);
    if ((nbf !== null && nbf > now + 60) || (exp !== null && exp <= now)) continue;
    if (TEST_KEYS.has(thumb)) kl.testKeys.add(thumb);
    kl.keys.set(thumb, [pub, kind]);
  }
  if (type === "directory") kl.proof = await directoryProof(hdrs, body, host, kl.keys, now);
  return kl;
}

// Appendix B: which keys signed this response for this host.
async function directoryProof(hdrs, body, host, keys, now) {
  const out = new Set();
  if (!hdrs["signature-input"] || !hdrs.signature || !hdrs["content-digest"]) return out;
  if (!(await digestOk(hdrs["content-digest"], body))) return out;
  let inputs, sigs;
  try { inputs = parseDictionary(hdrs["signature-input"]); sigs = parseDictionary(hdrs.signature); } catch { return out; }
  for (const [label, member] of Object.entries(inputs)) {
    const [covered, p] = member;
    if (!Array.isArray(covered) || !p.tag || p.tag.v !== DIRECTORY_TAG) continue;
    const thumb = p.keyid && p.keyid.t === "str" ? p.keyid.v : null;
    if (!thumb || !keys.has(thumb)) continue;
    const names = covered.map(([n, cp]) => [n.v, Object.keys(cp).join(",")]);
    if (!names.some(([n, k]) => n === "@authority" && k === "req") || !names.some(([n, k]) => n === "content-digest" && k === "")) continue;
    if (names.some(([n]) => n !== "@authority" && n !== "content-digest")) continue;
    const c = p.created, e = p.expires;
    if (!c || !c.isInt || !e || !e.isInt || c.v > now + 60 || e.v <= now) continue;
    const sig = sigs[label] && sigs[label][0];
    if (!sig || sig.t !== "bytes") continue;
    const lines = names.map(([n]) => (n === "@authority" ? `"@authority";req: ${host}` : `"content-digest": ${String(hdrs["content-digest"]).trim()}`));
    lines.push(`"@signature-params": ${serMember(member)}`);
    const [pub, kind] = keys.get(thumb);
    try { await checkSig(pub, kind, p.alg, sig.v, utf8(lines.join("\n"))); out.add(thumb); } catch { /* no proof */ }
  }
  return out;
}

function newResult(outcome, reason = "", extra = {}) {
  const r = { outcome, reason, agent: null, signatureAgent: null, keyid: null, label: null,
    domainProof: null, stale: false, created: null, expires: null, others: [], ...extra };
  Object.defineProperty(r, "verified", { get() { return this.outcome === VERIFIED; }, enumerable: false });
  return r;
}

/**
 * Checks Web Bot Auth signatures from any agent and keeps fetched key lists.
 * One Verifier per process is enough. Defaults follow the draft: signatures
 * live at most `maxLifetime` seconds (24 h), key lists are cached as their
 * Cache-Control says (at most `maxTtl`, at least `minTtl`), a list that cannot
 * be fetched keeps its last good copy for `maxStale` seconds (draft 6.10),
 * failures are cached `negativeTtl` seconds, and the RFC 9421 example keys
 * are refused. `fetch(url) -> [status, headers, body]` replaces the network
 * fetch (tests, or your own HTTP client: it must apply the same limits).
 */
export class Verifier {
  constructor({ maxLifetime = 86400, clockSkew = 60, timeout = 5, maxBytes = 65536, maxKeys = 32,
    allowPrivate = false, allowTestKeys = false, fetch = null, defaultTtl = 300, maxTtl = 86400,
    minTtl = 60, maxStale = 86400, negativeTtl = 60, refetchAfter = 60, maxEntries = 5000, publicBaseUrl } = {}) {
    Object.assign(this, { maxLifetime, clockSkew, timeout, maxBytes, maxKeys, allowPrivate, allowTestKeys,
      defaultTtl, maxTtl, minTtl, maxStale, refetchAfter, maxEntries, publicBaseUrl });
    this.negativeTtl = Math.min(negativeTtl, 300);
    this._fetch = fetch || ((url) => httpsGet(url, { timeout: this.timeout, maxBytes: this.maxBytes, allowPrivate: this.allowPrivate }));
    this._cache = new Map();
    this._neg = new Map();
    this._inflight = new Map();   // coalesces concurrent fetches for one identifier
  }

  _trim() {
    const now = Date.now() / 1000;
    for (const [k, v] of this._neg) if (v[0] <= now) this._neg.delete(k);
    const idle = [...new Set([...this._cache.keys(), ...this._neg.keys()])].filter((k) => !this._inflight.has(k))
      .sort((a, b) => (this._cache.get(a)?.fetched ?? 0) - (this._cache.get(b)?.fetched ?? 0));
    for (const k of idle.slice(0, Math.max(1, idle.length >> 2))) { this._cache.delete(k); this._neg.delete(k); }
  }

  async _resolve(ident, url, type, now, force = false) {
    const held = this._cache.get(ident);
    if (held && !force && now < held.freshUntil) return [held, false];
    const neg = this._neg.get(ident);
    if (neg && now < neg[0]) {
      if (held && now - held.fetched < this.maxStale) return [held, true];
      throw new Unverified(neg[1]);
    }
    if (this._inflight.has(ident)) return this._inflight.get(ident);
    if (!this._cache.has(ident) && this._cache.size + this._neg.size >= this.maxEntries) this._trim();
    const p = (async () => {
      let hdrs = {}, kl;
      try {
        let status, body;
        try { [status, hdrs, body] = await this._fetch(url); }
        catch (e) { throw e instanceof Unverified ? e : new Unverified(`fetching the key list failed: ${e.name || e.message}`); }
        const low = {};
        for (const [k, v] of Object.entries(hdrs || {})) low[String(k).toLowerCase()] = String(v);
        hdrs = low;
        kl = await parseList(status, hdrs, body instanceof Uint8Array ? body : utf8(String(body)), type, authority(url), now, this.maxKeys);
      } catch (e) {
        this._neg.set(ident, [now + this.negativeTtl, e.message]);
        if (held && now - held.fetched < this.maxStale) return [held, true];
        throw e;
      }
      kl.fetched = now;
      kl.freshUntil = now + Math.max(this.minTtl, ttl(hdrs, this.defaultTtl, this.maxTtl));
      this._cache.set(ident, kl);   // newer resolution wins (draft 4.4)
      this._neg.delete(ident);
      return [kl, false];
    })();
    this._inflight.set(ident, p);
    try { return await p; } finally { this._inflight.delete(ident); }
  }

  /** Fetch (or reuse) one agent's key list. */
  async resolve(signatureAgent, type = "directory", now) {
    now = Math.floor(now ?? Date.now() / 1000);
    const [ident, url] = identifier(signatureAgent, type);
    const [kl, stale] = await this._resolve(ident, url, type, now);
    return { agent: ident, keys: [...kl.keys.keys()].sort(), testKeys: [...kl.testKeys].sort(), domainProof: [...kl.proof].sort(), stale };
  }

  /**
   * Check every Web Bot Auth signature on one request. Pass a request object
   * (Fetch Request, Node/Express req, or {method, url, headers}) or the
   * options {method, url, headers}. The url must be the one the client sent,
   * including the query. Resolves to a result; the first verified signature
   * wins, otherwise the most telling failure.
   */
  async verify(request = null, { method, url, headers, now, publicBaseUrl } = {}) {
    try {
      if (request != null) [method, url, headers] = fromRequest(request, publicBaseUrl ?? this.publicBaseUrl);
      now = Math.floor(now ?? Date.now() / 1000);
      const msg = new Msg(method, url, headers);
      const si = msg.field("signature-input"), sg = msg.field("signature");
      if (!si && !sg) return newResult(UNSIGNED, "no signature");
      let inputs, sigs;
      try { inputs = parseDictionary(si || ""); sigs = parseDictionary(sg || ""); }
      catch (e) { return newResult(INVALID, `cannot parse Signature-Input or Signature: ${e.message}`); }
      const results = [];
      for (const [label, member] of Object.entries(inputs)) {
        const [covered, p] = member;
        if (!Array.isArray(covered) || !p.tag || p.tag.t !== "str" || p.tag.v !== TAG) continue;   // draft 5.4
        results.push(await this._one(msg, label, member, sigs[label], now));
      }
      if (!results.length) return newResult(UNSIGNED, "no web-bot-auth signature");
      const rank = { [VERIFIED]: 0, [INVALID]: 1, [UNVERIFIED]: 2 };
      results.sort((a, b) => rank[a.outcome] - rank[b.outcome]);
      results[0].others = results.slice(1);
      return results[0];
    } catch (e) {
      if (e instanceof Unverified) return newResult(UNVERIFIED, e.message);
      throw e;
    }
  }

  async _one(msg, label, member, sigMember, now) {
    const [covered, p] = member;
    const int = (x) => (x && x.t === "num" && x.isInt ? x.v : null);
    const r = newResult(UNVERIFIED, "", { label, keyid: p.keyid && p.keyid.t === "str" ? p.keyid.v : null,
      created: int(p.created), expires: int(p.expires) });
    try {
      const sig = sigMember && sigMember[0];
      if (!sig || sig.t !== "bytes") throw new Invalid("no matching Signature value");
      const created = int(p.created), expires = int(p.expires);
      if (created === null || expires === null) throw new Invalid("created and expires are required");
      if (created > now + this.clockSkew) throw new Invalid("signature created in the future");
      if (expires <= now - this.clockSkew) throw new Invalid("signature expired");
      if (this.maxLifetime != null && expires - created > this.maxLifetime)
        throw new Invalid(`signature valid for ${expires - created} s, more than ${this.maxLifetime} s`);
      if (r.keyid === null) throw new Invalid("keyid is required");
      if (!covered.some(([n]) => n.v === "@authority" || n.v === "@target-uri"))
        throw new Invalid("signature covers neither @authority nor @target-uri");
      const base = msg.base(covered, member);
      // the Signature-Agent member this signature covers (draft 5.2.1, 5.2.2)
      const agentParts = covered.filter(([n]) => n.v === "signature-agent").map(([, cp]) => cp);
      if (agentParts.length !== 1)
        throw new Unverified(agentParts.length ? "signature must cover exactly one Signature-Agent member" : "signature does not cover Signature-Agent");
      const raw = msg.field("signature-agent") || "";
      let value, mp;
      try {
        if (agentParts[0].key) [value, mp] = parseDictionary(raw)[agentParts[0].key.v];
        else [value, mp] = parseItem(raw);   // legacy sf-string form
      } catch (e) {
        throw new Unverified(`cannot read Signature-Agent: ${e.message}`);
      }
      if (!value || value.t !== "str") throw new Unverified("Signature-Agent member is not a string");
      r.signatureAgent = value.v;
      const type = mp.type ? String(mp.type.v) : "directory";
      const [ident, url] = identifier(value.v, type);
      let [kl, stale] = await this._resolve(ident, url, type, now);
      if (!kl.keys.has(r.keyid) && !stale && now - kl.fetched >= this.refetchAfter)
        [kl, stale] = await this._resolve(ident, url, type, now, true);   // a key may have been added
      if (!kl.keys.has(r.keyid)) throw new Unverified("the key list does not hold this keyid");
      if (kl.testKeys.has(r.keyid) && !this.allowTestKeys) throw new Invalid("signed with a published test key (draft 6.8)");
      const [pub, kind] = kl.keys.get(r.keyid);
      await checkSig(pub, kind, p.alg, sig.v, base);
      Object.assign(r, { outcome: VERIFIED, agent: ident, stale,
        domainProof: type === "directory" ? kl.proof.has(r.keyid) : null,
        reason: "signature verified" + (stale ? " with a stale key list" : "") });
    } catch (e) {
      if (e instanceof Invalid) Object.assign(r, { outcome: INVALID, reason: e.message });
      else if (e instanceof Unverified || e instanceof SFError) Object.assign(r, { outcome: UNVERIFIED, reason: e.message });
      else throw e;
    }
    return r;
  }
}

let _default = null;
/** Verifier.verify on a shared default Verifier. */
export function verify(request = null, opts = {}) {
  _default ||= new Verifier();
  return _default.verify(request, opts);
}

// internals for the test suite
export const _internals = { Msg, checkSig, loadJwk, Invalid, formEncode, parseQuery, normPath };
