// JS SDK webbotauth verifier: the same checks as verify_test.py, in Node.
//
// Sections:
//   1  RFC 9421 Appendix B vectors (signature base builder; Ed25519, RSA-PSS, ECDSA)
//   2  draft-00 Appendix E vectors through verify() (dict + legacy; E.2.3 domain proof)
//   3  interop: JS signer, Python signer, Cloudflare's npm web-bot-auth 0.2 signer -> JS verifier
//   4  refusals
//   5  cache
//   6  SSRF limits of httpsGet (real sockets: local TLS server + public hosts)
//   7  request objects (Fetch Request, node:http server)
//   8  live: chatgpt.com, Cloudflare's demo list, a throwaway agent on authyouragent.com
// Run: node tests-private/wba/verify_test.mjs [--no-live]
import fs from "node:fs";
import { webcrypto } from "node:crypto";
const crypto = globalThis.crypto || webcrypto;
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as W from "../../sdk-js/src/webbotauth.js";
import * as S from "../../sdk-js/src/_sfv.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../..");
const KEYS = process.env.RFC_KEYS || "/root/.hermes/cache/scratch/wbagh/examples/rfc9421-keys";
const LIVE = !process.argv.includes("--no-live");
const PY = process.env.PYTHON || path.join(REPO, ".venv/bin/python");
const ok = [];
const check = (name, cond, extra = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}` + (extra && !cond ? `  [${typeof extra === "string" ? extra : JSON.stringify(extra)}]` : ""));
  ok.push(!!cond);
};
const section = (t) => console.log(`\n== ${t}`);
const unwrap = (s) => { // RFC 8792 single-backslash unwrapping
  let out = "";
  for (const ln of s.replace(/^\n+|\n+$/g, "").split("\n")) out = out.endsWith("\\") ? out.slice(0, -1) + ln.trimStart() : out + (out ? "\n" : "") + ln;
  return out;
};
const show = (r) => `${r.outcome} ${r.agent || r.signatureAgent || "-"} ${r.reason}`;
const te = new TextEncoder();
const b64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const DIR_HDRS = { "content-type": W.MEDIA_TYPE, "cache-control": "max-age=300" };
const dirUrl = (o) => o.replace(/\/+$/, "") + W.WELL_KNOWN;

class Fake {
  constructor(routes = {}) { this.routes = { ...routes }; this.calls = []; this.fn = this.call.bind(this); }
  async call(url) {
    this.calls.push(url);
    const r = this.routes[url];
    if (r === undefined) throw new Error("no route");
    if (r instanceof Error) throw r;
    return r;
  }
}
async function directory(...jwks) {
  const keys = [];
  for (const j of jwks) keys.push(j.kty === "OKP" ? { ...j, kid: await W.thumbprint(j) } : { ...j });
  return te.encode(JSON.stringify({ keys }));
}

// ── keys ──
const ed = JSON.parse(fs.readFileSync(`${KEYS}/ed25519.json`));
const ED_PRIV = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: ed.x, d: ed.d }, { name: "Ed25519" }, true, ["sign"]);
const ED_PUBKEY = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: ed.x }, { name: "Ed25519" }, true, ["verify"]);
const ED_KEY = { privateKey: ED_PRIV, publicKey: ED_PUBKEY };
const ED_PUB = { kty: "OKP", crv: "Ed25519", x: ed.x };
const rsaJ = JSON.parse(fs.readFileSync(`${KEYS}/rsapss.json`));
const RSA_PUB = { kty: "RSA", n: rsaJ.n, e: rsaJ.e, alg: "PS512" };

// ═════════════ 1. RFC 9421 Appendix B ═════════════
section("1 RFC 9421 Appendix B vectors");
const REQ = new W._internals.Msg("POST", "https://example.com/foo?param=Value&Pet=dog", {
  Host: "example.com", Date: "Tue, 20 Apr 2021 02:07:55 GMT", "Content-Type": "application/json",
  "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
  "Content-Length": "18" });
async function bVector(si, sigB64, jwk, alg) {
  const [, member] = Object.entries(S.parseDictionary(si))[0];
  const base = REQ.base(member[0], member);
  const [, pub, kind] = await W._internals.loadJwk(jwk);
  try { await W._internals.checkSig(pub, kind, { t: "str", v: alg }, b64(sigB64), base); return [true, base]; }
  catch { return [false, new TextDecoder().decode(base)]; }
}
let [good, base] = await bVector(unwrap(`sig-b26=("date" "@method" "@path" "@authority" \\
  "content-type" "content-length");created=1618884473\\
  ;keyid="test-key-ed25519"`), "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==", ED_PUB, "ed25519");
check("B.2.6 ed25519: base rebuilt, published signature verifies", good, base);
[good, base] = await bVector(unwrap(`sig-b22=("@authority" "content-digest" \\
  "@query-param";name="Pet");created=1618884473\\
  ;keyid="test-key-rsa-pss";tag="header-example"`), unwrap(`LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ\\
  EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT\\
  8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA\\
  RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd\\
  4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK\\
  UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==`), RSA_PUB, "rsa-pss-sha512");
check("B.2.2 rsa-pss-sha512 with @query-param + content-digest verifies", good, base);
[good, base] = await bVector(unwrap(`sig-b23=("date" "@method" "@path" "@query" \\
  "@authority" "content-type" "content-digest" "content-length")\\
  ;created=1618884473;keyid="test-key-rsa-pss"`), unwrap(`bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB\\
  iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU\\
  xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1\\
  pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9\\
  bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z\\
  JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==`), RSA_PUB, "rsa-pss-sha512");
check("B.2.3 full coverage incl. @query verifies", good, base);
{
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, te.encode("x")));
  const [, pub, kind] = await W._internals.loadJwk({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y });
  let v = true;
  try { await W._internals.checkSig(pub, kind, { t: "str", v: "ecdsa-p256-sha256" }, sig, te.encode("x")); } catch { v = false; }
  check("ecdsa-p256-sha256 raw r||s verifies", v);
}
const qp = new W._internals.Msg("GET", "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&" +
  "bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something", {});
const vals = ["var", "bar", "fa%C3%A7ade%22%3A%20"].map((n) => qp.component("@query-param", { name: { t: "str", v: n } }));
check("2.2.8 @query-param encoding matches the RFC", JSON.stringify(vals) === JSON.stringify(["this%20is%20a%20big%0Amultiline%20value", "with%20plus%20whitespace", "something"]), vals);
let threw = false;
try { qp.component("@query-param", { name: { t: "str", v: "nope" } }); } catch (e) { threw = e instanceof W._internals.Invalid; }
check("missing @query-param is an error", threw);
check("SFV round trip: inner list with params, bool, bytes, token, decimal",
  ['sig2=("@authority" "signature-agent";key="agent2");created=1;keyid="k";tag="web-bot-auth"', "a=1, b=?0, d=:QQ==:, e=1.5, f=tok-1, g=(-5.25)"]
    .every((s) => Object.entries(S.parseDictionary(s)).map(([k, v]) => `${k}=${S.serMember(v)}`).join(", ") === s));

// ═════════════ 2. draft Appendix E ═════════════
section("2 draft-00 Appendix E vectors through verify()");
const TA = "https://signature-agent.test";
const vecFetch = new Fake({ [dirUrl(TA)]: [200, DIR_HDRS, await directory(ED_PUB, RSA_PUB)] });
const V = new W.Verifier({ fetch: vecFetch.fn, allowTestKeys: true, maxLifetime: null });
const E = {
  "E.2.1 ed25519, dictionary Signature-Agent": ['agent2="https://signature-agent.test"', unwrap(`sig2=("@authority" "signature-agent";key="agent2")\\
 ;created=1735689600\\
 ;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"\\
 ;alg="ed25519"\\
 ;expires=4889289600\\
 ;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`),
    "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:"],
  "E.2.2 ed25519, legacy string Signature-Agent": ['"https://signature-agent.test"', unwrap(`sig2=("@authority" "signature-agent")\\
 ;created=1735689600\\
 ;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"\\
 ;alg="ed25519"\\
 ;expires=1735693200\\
 ;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`),
    "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:"],
  "E.1.1 rsa-pss-sha512, dictionary Signature-Agent": ['agent2="https://signature-agent.test"', unwrap(`sig2=("@authority" "signature-agent";key="agent2")\\
 ;created=1735689600\\
 ;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"\\
 ;alg="rsa-pss-sha512"\\
 ;expires=4889289600\\
 ;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"`),
    "sig2=:gHzpLNeHaHIO19NaJH9YMW5dcVSi2s0wOMBr6p18vcofS106sfC4KBIS0/szPlBBd1vIcyQ88B6CTEWIhRAiVrb9zfX0mx1aG12CSGWcYkSirHeyTxhbuJvXd27ed6skWoy4PjXItq38936ivUQjfdIwXh1aX6HxkAC3vRnEdSNfntkLWeEuIQ5BLIOBGE39fSwg27Qjq6OVWYas/9/aFUr3HA34MXWYdp+//cvlEKDp3kRoLOw9ro0AOr6srHrTeEtxon2afcws1aZVSlPdd2fZSEIGmw9HAHLDCEkFTERu1gH2k/zIEqgy7CAYXI9E5slog0cLg/Vc6+f8gih33g==:"],
  "E.1.2 rsa-pss-sha512, legacy string Signature-Agent": ['"https://signature-agent.test"', unwrap(`sig2=("@authority" "signature-agent")\\
 ;created=1735689600\\
 ;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"\\
 ;alg="rsa-pss-sha512"\\
 ;expires=1735693200\\
 ;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"`),
    "sig2=:I1QWNzGXdP1a4dSvOHLCVOOanEYHDk+ZsVxM9MLX/p4ko69ghKwR5EOtAD96g7g4GWP7lmpM/jFAf9q8EFRDTPLjUXySwMv4YPgabv2LQihTJG2y8a2m6IGltyruwQNiqSJVUuRaG9+b17CGmAMFZh30X6GXLdQJrCARpeTqPwp2DC+a8haDE/VE5EruqzjA5/2mKwvrkzkSqeW5tOVtFwWRRHIOidquf/8Je6kM9mhgkg4arudLA5SL4wyyYE1jURIgcOl8agrfdJ5Def23DIRtiOLRa8jT9cpTLFAuFHN+mrZA/LH9h0gSIg1cPb+0cMASee5uku1KjWcFer7jWA==:"],
};
for (const [name, [agent, si, sg]] of Object.entries(E)) {
  const hdrs = { "Signature-Agent": agent, "Signature-Input": si, Signature: sg };
  let r = await V.verify(null, { method: "GET", url: "https://example.com/", headers: hdrs, now: 1735690000 });
  check(`${name}: verified, agent = well-known URL`, r.verified && r.agent === dirUrl(TA), show(r));
  r = await V.verify(null, { method: "GET", url: "https://example.org/", headers: hdrs, now: 1735690000 });
  check(`${name}: refused for another authority`, r.outcome === W.INVALID, show(r));
}
const e21 = Object.fromEntries(["Signature-Agent", "Signature-Input", "Signature"].map((k, i) => [k, E["E.2.1 ed25519, dictionary Signature-Agent"][i]]));
let r = await new W.Verifier({ fetch: vecFetch.fn, maxLifetime: null }).verify(null, { method: "GET", url: "https://example.com/", headers: e21, now: 1735690000 });
check("draft 6.8: the RFC test key is refused by default", r.outcome === W.INVALID && r.reason.includes("test key"), show(r));
r = await new W.Verifier({ fetch: vecFetch.fn, allowTestKeys: true }).verify(null, { method: "GET", url: "https://example.com/", headers: e21, now: 1735690000 });
check("a 99-year signature is refused by default (maxLifetime 24 h)", r.outcome === W.INVALID && r.reason.includes("more than"), show(r));
const E23_BODY = te.encode('{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}');
const E23_HDRS = { ...DIR_HDRS, "content-digest": "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:",
  "signature-input": 'binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"',
  signature: "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:" };
const ED_THUMB = await W.thumbprint(ED_PUB);
let kl = await W.parseList(200, E23_HDRS, E23_BODY, "directory", "signature-agent.test", 1735690000);
check("E.2.3 directory proof validates for signature-agent.test", kl.proof.has(ED_THUMB));
kl = await W.parseList(200, E23_HDRS, E23_BODY, "directory", "copy.example", 1735690000);
check("E.2.3 the same response served by another host carries no proof", kl.proof.size === 0);
kl = await W.parseList(200, E23_HDRS, te.encode(new TextDecoder().decode(E23_BODY).replace('"use":"sig"', '"use":"enc"')), "directory", "signature-agent.test", 1735690000);
check("E.2.3 a changed body breaks the proof (content-digest)", kl.proof.size === 0);
kl = await W.parseList(200, E23_HDRS, E23_BODY, "directory", "signature-agent.test", 1735689000);
check("B.1: a proof created in the future is rejected", kl.proof.size === 0);

// ═════════════ 3. interop ═════════════
section("3 interop");
const AG = "https://agent.example";
const KEY = await W.newKey();
const PUB = await W.publicJwk(KEY);
const THUMB = await W.thumbprint(PUB);
const f3 = new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, await directory(PUB)] });
const V3 = new W.Verifier({ fetch: f3.fn });
const url = "https://shop.example/p/1?colour=blue";
let h = await W.signRequest(KEY, "GET", url, AG);
r = await V3.verify(null, { method: "GET", url, headers: h });
check("JS signer -> verified", r.verified && r.agent === dirUrl(AG) && r.keyid === THUMB, show(r));
check("result has created/expires/label", r.label === "sig1" && r.expires - r.created === W.REQUEST_LIFETIME);
// the Python SDK signs, the JS SDK verifies (and the other way round)
if (!fs.existsSync(PY)) console.log("  SKIP  Python interop (no " + PY + ")");
else {
const pyOut = JSON.parse(execFileSync(PY, ["-c", `
import sys, json; sys.path.insert(0, "${REPO}/sdk")
from authyouragent import webbotauth as W
k = W.new_key(); u = "${url}"
print(json.dumps({"jwk": W.public_jwk(k), "headers": W.sign_request(k, "GET", u, "${AG}")}))`], { encoding: "utf8" }));
const f3p = new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, await directory(pyOut.jwk)] });
r = await new W.Verifier({ fetch: f3p.fn }).verify(null, { method: "GET", url, headers: pyOut.headers });
check("Python SDK signer -> JS verifier: verified", r.verified, show(r));
const jsSigned = JSON.stringify({ jwk: PUB, headers: await W.signRequest(KEY, "GET", url, AG) });
const pyVerdict = execFileSync(PY, ["-c", `
import sys, json; sys.path.insert(0, "${REPO}/sdk")
from authyouragent import webbotauth as W
d = json.loads(sys.stdin.read())
body = json.dumps({"keys": [dict(d["jwk"], kid=W.thumbprint(d["jwk"]))]}).encode()
v = W.Verifier(fetch=lambda u: (200, {"content-type": W.MEDIA_TYPE}, body))
print(v.verify(method="GET", url="${url}", headers=d["headers"]).outcome)`], { input: jsSigned, encoding: "utf8" }).trim();
check("JS signer -> Python verifier: verified", pyVerdict === "verified", pyVerdict);
}
let cf = null;
if (globalThis.crypto) try {
  cf = JSON.parse(execFileSync("node", ["cf_sign.mjs"], { cwd: HERE, input: JSON.stringify({ url, method: "GET", agent: `sig1="${AG}"` }), encoding: "utf8" }));
} catch (e) { cf = null; }
if (fs.existsSync(path.join(HERE, "node_modules/web-bot-auth")) && globalThis.crypto) {
  check("Cloudflare's signer ran", cf !== null);
  if (cf) {
    const fcf = new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, await directory(cf.jwk)] });
    const Vc = new W.Verifier({ fetch: fcf.fn });
    r = await Vc.verify(null, { method: "GET", url, headers: cf.headers });
    check("Cloudflare-signed request (dictionary form) -> verified", r.verified && r.keyid === cf.keyid, show(r));
    r = await Vc.verify(null, { method: "POST", url: "https://shop.example/other", headers: cf.headers });
    check("Cloudflare signs @authority only, so another path/method still verifies (draft 5.2)", r.verified, show(r));
    const cf2 = JSON.parse(execFileSync("node", ["cf_sign.mjs"], { cwd: HERE, input: JSON.stringify({ url, method: "GET", agent: `sig1="${AG}"`, extra: ["@method", "@path"] }), encoding: "utf8" }));
    const Vc2 = new W.Verifier({ fetch: new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, await directory(cf2.jwk)] }).fn });
    check("Cloudflare + @method @path -> verified", (await Vc2.verify(null, { method: "GET", url, headers: cf2.headers })).verified);
    check("... and refused on another path", (await Vc2.verify(null, { method: "GET", url: "https://shop.example/p/2", headers: cf2.headers })).outcome === W.INVALID);
  }
} else console.log("  SKIP  Cloudflare interop (needs the web-bot-auth npm package and Node 20+)");

// ═════════════ 4. refusals ═════════════
section("4 refusals");
const f4 = new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, await directory(PUB)] });
const V4 = new W.Verifier({ fetch: f4.fn });
const NOW = Math.floor(Date.now() / 1000);
const signed = (o = {}) => W.signRequest(o.key || KEY, o.method || "GET", o.url || url, o.agent || AG, { now: o.now });
const outcome = (hd, o = {}) => (o.v || V4).verify(null, { method: o.method || "GET", url: o.u || url, headers: hd, now: o.now });
r = await outcome(await signed(), { u: "https://shop.example/p/2" }); check("other path -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await signed(), { method: "POST" }); check("other method -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await signed(), { u: "https://evil.example/p/1" }); check("other host -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await signed({ now: NOW - 1000 })); check("expired -> invalid", r.outcome === W.INVALID && r.reason.includes("expired"), show(r));
r = await outcome(await signed({ now: NOW + 1000 })); check("created in the future -> invalid", r.outcome === W.INVALID && r.reason.includes("future"), show(r));
h = await signed(); h.Signature = h.Signature.slice(0, 10) + (h.Signature[10] !== "A" ? "A" : "B") + h.Signature.slice(11);
r = await outcome(h); check("altered signature bytes -> invalid", r.outcome === W.INVALID, show(r));
f4.routes[dirUrl("https://other.example")] = [200, DIR_HDRS, await directory(PUB)];
h = await signed(); h["Signature-Agent"] = '"https://other.example"';
r = await outcome(h); check("swapped Signature-Agent (other site lists the same key) -> invalid, it is covered", r.outcome === W.INVALID && r.agent === null, show(r));
const OTHER = await W.newKey();
r = await outcome(await signed({ key: OTHER })); check("key not in the agent's list -> unverified", r.outcome === W.UNVERIFIED && r.reason.includes("does not hold"), show(r));
const VICTIM = "https://victim.example";
f4.routes[dirUrl(VICTIM)] = [200, DIR_HDRS, await directory(await W.publicJwk(await W.newKey()))];
r = await outcome(await signed({ agent: VICTIM }));
check("5.4 pair rule: AG's key claiming VICTIM -> unverified (not attributed to VICTIM)", r.outcome === W.UNVERIFIED && r.agent === null, show(r));
for (const [bad, why] of [["http://agent.example", "http"], ["https://agent.example/keys", "path"], ["https://agent.example?x=1", "query"],
  ["https://user@agent.example", "userinfo"], ["https://agent.example:99999", "port"]]) {
  r = await outcome(await signed({ agent: bad }));
  check(`Signature-Agent with ${why} -> unverified, no fetch`, r.outcome === W.UNVERIFIED, show(r));
}
check("no fetch was made for any bad Signature-Agent", f4.calls.every((c) => [AG, VICTIM, "https://other.example"].includes(c.split("/.well-known")[0])), f4.calls);
h = await signed(); h["Signature-Agent"] = 'sig1="https://agent.example";type=cimd';
r = await outcome(h); check("unsupported type=cimd -> not verified (never guessed)", r.outcome === W.UNVERIFIED || r.outcome === W.INVALID, show(r));

// arbitrary signatures, built with the verifier's own base builder
async function custom(components, params, agentHdr, { key = KEY, label = "sig1", u = url, method = "GET", signHdr } = {}) {
  const ser = (v) => (typeof v === "number" ? { t: "num", v, isInt: true } : { t: "str", v });
  const covered = components.map(([c, p]) => [{ t: "str", v: c }, Object.fromEntries(Object.entries(p).map(([k, v]) => [k, ser(v)]))]);
  const member = [covered, Object.fromEntries(Object.entries(params).map(([k, v]) => [k, ser(v)]))];
  const hdr = signHdr || agentHdr;
  const msg = new W._internals.Msg(method, u, hdr ? { "Signature-Agent": hdr } : {});
  const b = msg.base(covered, member);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, b));
  const out = { "Signature-Input": `${label}=${S.serMember(member)}`, Signature: `${label}=:${Buffer.from(sig).toString("base64")}:` };
  if (agentHdr) out["Signature-Agent"] = agentHdr;
  return out;
}
const P = (o = {}) => ({ created: NOW, expires: NOW + 300, keyid: THUMB, alg: "ed25519", tag: "web-bot-auth", ...o });
const without = (k) => { const p = P(); delete p[k]; return p; };
r = await outcome(await custom([["@authority", {}]], P(), `"${AG}"`)); check("does not cover Signature-Agent -> unverified", r.outcome === W.UNVERIFIED, show(r));
r = await outcome(await custom([["@path", {}], ["signature-agent", {}]], P(), `"${AG}"`)); check("covers neither @authority nor @target-uri -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@target-uri", {}], ["signature-agent", { key: "sig1" }]], P(), `sig1="${AG}"`)); check("@target-uri + dictionary member -> verified", r.verified, show(r));
r = await outcome(await custom([["@target-uri", {}], ["signature-agent", { key: "sig1" }]], P(), `sig1="${AG}"`), { u: url + "&x=2" }); check("@target-uri: changed query -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", {}]], P({ alg: "hmac-sha256" }), `"${AG}"`)); check("hmac-sha256 -> invalid (6.4)", r.outcome === W.INVALID && r.reason.includes("shared"), show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", {}]], P({ alg: "rsa-pss-sha512" }), `"${AG}"`)); check("alg not matching the key -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", {}]], without("expires"), `"${AG}"`)); check("no expires -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", {}]], without("keyid"), `"${AG}"`)); check("no keyid -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", {}]], P({ tag: "other" }), `"${AG}"`)); check("tag other than web-bot-auth -> unsigned (not ours to judge)", r.outcome === W.UNSIGNED, show(r));
r = await outcome({}); check("no headers -> unsigned", r.outcome === W.UNSIGNED, show(r));
r = await outcome({ "Signature-Input": "sig1=(", Signature: "sig1=:AA==:" }); check("garbled Signature-Input -> invalid", r.outcome === W.INVALID, show(r));
r = await outcome(await custom([["@authority", {}], ["signature-agent", { key: "a" }], ["signature-agent", { key: "b" }]], P(), `a="${AG}", b="${VICTIM}"`));
check("covers two Signature-Agent members -> unverified (attribution ambiguous)", r.outcome === W.UNVERIFIED, show(r));
const BOTH = `s1="${AG}", s2="${AG}"`;
const goodH = await custom([["@authority", {}], ["signature-agent", { key: "s2" }]], P(), null, { label: "s2", signHdr: BOTH });
const badH = await custom([["@authority", {}], ["signature-agent", { key: "s1" }]], P({ keyid: await W.thumbprint(await W.publicJwk(OTHER)) }), null, { key: OTHER, label: "s1", signHdr: BOTH });
r = await outcome({ "Signature-Agent": BOTH, "Signature-Input": badH["Signature-Input"] + ", " + goodH["Signature-Input"], Signature: badH.Signature + ", " + goodH.Signature });
check("two signatures, one unknown key + one good -> verified, other listed", r.verified && r.label === "s2" && r.others.length === 1, show(r));
const dir1 = (j) => te.encode(JSON.stringify({ keys: [j] }));
f4.routes[dirUrl("https://kid.example")] = [200, DIR_HDRS, dir1({ ...PUB, kid: "label-1" })];
r = await outcome(await signed({ agent: "https://kid.example" })); check("directory kid not equal to the thumbprint -> key ignored", r.outcome === W.UNVERIFIED, show(r));
f4.routes[dirUrl("https://exp.example")] = [200, DIR_HDRS, dir1({ ...PUB, exp: NOW - 10 })];
r = await outcome(await signed({ agent: "https://exp.example" })); check("key past its exp -> ignored", r.outcome === W.UNVERIFIED, show(r));
f4.routes[dirUrl("https://priv.example")] = [200, DIR_HDRS, dir1({ ...PUB, d: "AAAA" })];
r = await outcome(await signed({ agent: "https://priv.example" })); check("entry carrying a private key -> ignored", r.outcome === W.UNVERIFIED, show(r));
f4.routes[dirUrl("https://ctype.example")] = [200, { "content-type": "application/json" }, await directory(PUB)];
r = await outcome(await signed({ agent: "https://ctype.example" })); check("directory with the wrong media type -> unverified", r.outcome === W.UNVERIFIED && r.reason.includes("served as"), show(r));
const many = [];
for (let i = 0; i < 40; i++) many.push(await W.publicJwk(await W.newKey()));
f4.routes[dirUrl("https://many.example")] = [200, DIR_HDRS, await directory(...many, PUB)];
r = await outcome(await signed({ agent: "https://many.example" })); check("more than 32 keys -> unverified", r.outcome === W.UNVERIFIED && r.reason.includes("more than"), show(r));
f4.routes[dirUrl("https://redir.example")] = [302, { location: dirUrl(AG) }, new Uint8Array()];
r = await outcome(await signed({ agent: "https://redir.example" })); check("redirect answer -> unverified, not followed", r.outcome === W.UNVERIFIED && r.reason.includes("302"), show(r));
f4.routes["https://jw.example/keys.json?v=1"] = [200, { "content-type": "application/json" }, dir1({ ...PUB, kid: "my-label" })];
r = await outcome(await custom([["@authority", {}], ["signature-agent", { key: "sig1" }]], P(), 'sig1="https://jw.example/keys.json?v=1";type=jwks_uri'));
check("type=jwks_uri: verified, identifier drops the query, operator kid allowed", r.verified && r.agent === "https://jw.example/keys.json", show(r));
check("identifier normalisation: AGENT.example and agent.example share one entry", W.identifier("https://AGENT.example")[0] === W.identifier("https://agent.example/")[0]);

// ═════════════ 5. cache ═════════════
section("5 cache");
const MA = (n) => ({ "content-type": W.MEDIA_TYPE, "cache-control": `max-age=${n}` });
const f5 = new Fake({ [dirUrl(AG)]: [200, MA(600), await directory(PUB)] });
const V5 = new W.Verifier({ fetch: f5.fn });
for (let i = 0; i < 5; i++) await V5.verify(null, { method: "GET", url, headers: await signed({ now: NOW + i }), now: NOW + i });
check("max-age 600: five requests, one fetch", f5.calls.length === 1, f5.calls);
await V5.verify(null, { method: "GET", url, headers: await signed({ now: NOW + 700 }), now: NOW + 700 });
check("after max-age: refetched", f5.calls.length === 2, f5.calls);
f5.routes[dirUrl(AG)] = [200, MA(600), await directory(await W.publicJwk(await W.newKey()))];
r = await V5.verify(null, { method: "GET", url, headers: await signed({ now: NOW + 1400 }), now: NOW + 1400 });
check("removed key stops verifying after the cached copy expires", r.outcome === W.UNVERIFIED, show(r));
const f5b = new Fake({ [dirUrl(AG)]: [200, MA(60), await directory(PUB)] });
const V5b = new W.Verifier({ fetch: f5b.fn });
await V5b.verify(null, { method: "GET", url, headers: await signed({ now: NOW }), now: NOW });
f5b.routes[dirUrl(AG)] = new Error("connection refused");
r = await V5b.verify(null, { method: "GET", url, headers: await signed({ now: NOW + 120 }), now: NOW + 120 });
check("outage after expiry: still verified from the old copy, stale=true", r.verified && r.stale, show(r));
await V5b.verify(null, { method: "GET", url, headers: await signed({ now: NOW + 130 }), now: NOW + 130 });
check("negative cache: no new fetch 10 s later", f5b.calls.length === 2, f5b.calls);
r = await V5b.verify(null, { method: "GET", url, headers: await signed({ now: NOW + 90000 }), now: NOW + 90000 });
check("outage past maxStale (24 h): unverified", r.outcome === W.UNVERIFIED, show(r));
f5b.routes[dirUrl(AG)] = [500, {}, new Uint8Array()];
r = await new W.Verifier({ fetch: f5b.fn }).verify(null, { method: "GET", url, headers: await signed({ now: NOW }), now: NOW });
check("first fetch fails (HTTP 500), nothing cached: unverified", r.outcome === W.UNVERIFIED && r.reason.includes("500"), show(r));
const f5d = new Fake({ [dirUrl(AG)]: [200, { "content-type": W.MEDIA_TYPE, "cache-control": "no-store" }, await directory(PUB)] });
const V5d = new W.Verifier({ fetch: f5d.fn });
for (let i = 0; i < 3; i++) await V5d.verify(null, { method: "GET", url, headers: await signed({ now: NOW + i }), now: NOW + i });
check("no-store: reused for minTtl (60 s), one fetch for 3 requests", f5d.calls.length === 1, f5d.calls);
const V5e = new W.Verifier({ fetch: f5d.fn, minTtl: 0 });
for (let i = 0; i < 3; i++) await V5e.verify(null, { method: "GET", url, headers: await signed({ now: NOW + i }), now: NOW + i });
check("no-store with minTtl=0: fetched every time", f5d.calls.length === 4, f5d.calls);
const NEW = await W.newKey();
const f5f = new Fake({ [dirUrl(AG)]: [200, MA(3600), await directory(PUB)] });
const V5f = new W.Verifier({ fetch: f5f.fn });
await V5f.verify(null, { method: "GET", url, headers: await signed({ now: NOW }), now: NOW });
f5f.routes[dirUrl(AG)] = [200, MA(3600), await directory(PUB, await W.publicJwk(NEW))];
r = await V5f.verify(null, { method: "GET", url, headers: await signed({ key: NEW, now: NOW + 10 }), now: NOW + 10 });
check("new key within refetchAfter: not refetched yet", r.outcome === W.UNVERIFIED && f5f.calls.length === 1, show(r));
r = await V5f.verify(null, { method: "GET", url, headers: await signed({ key: NEW, now: NOW + 120 }), now: NOW + 120 });
check("new key after refetchAfter: refetched, verified", r.verified && f5f.calls.length === 2, show(r));
let slowCalls = 0;
const dirPub = await directory(PUB);
const V5g = new W.Verifier({ fetch: async () => { slowCalls++; await new Promise((s) => setTimeout(s, 300)); return [200, DIR_HDRS, dirPub]; } });
const res = await Promise.all(Array.from({ length: 8 }, async () => V5g.verify(null, { method: "GET", url, headers: await signed() })));
check("8 concurrent requests, one fetch, all verified", slowCalls === 1 && res.every((x) => x.verified), [slowCalls, res.map((x) => x.outcome)]);
const V5h = new W.Verifier({ fetch: async () => [200, DIR_HDRS, dirPub], maxEntries: 20 });
for (let i = 0; i < 60; i++) await V5h.verify(null, { method: "GET", url, headers: await signed({ agent: `https://a${i}.example` }) });
check("maxEntries bounds memory (60 agents, limit 20)", V5h._cache.size <= 20 && V5h._neg.size <= 20, [V5h._cache.size, V5h._neg.size]);
check("max-age capped at maxTtl and Age subtracted", W.ttl({ "cache-control": "max-age=999999" }, 300, 86400) === 86400 && W.ttl({ "cache-control": "max-age=600", age: "500" }, 300, 86400) === 100);

// ═════════════ 6. SSRF limits ═════════════
section("6 SSRF limits of httpsGet");
const refused = async (u, o = {}) => { try { await W.httpsGet(u, o); return null; } catch (e) { return e instanceof W.Unverified ? e.message : `OTHER ${e}`; } };
for (const t of ["https://127.0.0.1/", "https://localhost/", "https://[::1]/", "https://169.254.169.254/", "https://10.1.2.3/",
  "https://192.168.1.1/", "https://[::ffff:127.0.0.1]/", "https://0.0.0.0/", "https://100.64.0.1/", "https://[fd00::1]/", "https://[fe80::1]/"]) {
  const why = await refused(t);
  check(`${t} refused before connecting`, why && why.includes("non-public"), why);
}
check("http:// refused", (await refused("http://example.com/")) !== null);
check("isPublicAddress: 8.8.8.8 and 2606:4700:: are public", W.isPublicAddress("8.8.8.8") && W.isPublicAddress("2606:4700::1111"));
const td = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), "wbajs-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
  "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", `${td}/k.pem`, "-out", `${td}/c.pem`], { stdio: "ignore" });
const CA = fs.readFileSync(`${td}/c.pem`, "utf8");
let targetHits = 0;
const srv = https.createServer({ key: fs.readFileSync(`${td}/k.pem`), cert: CA }, (req, resp) => {
  const p = req.url;
  if (p === "/big") { const b = Buffer.alloc(200000, "x"); resp.writeHead(200, { "content-length": b.length }); resp.end(b); }
  else if (p === "/bigchunked") { resp.writeHead(200); for (let i = 0; i < 20; i++) resp.write(Buffer.alloc(10000, "x")); resp.end(); }
  else if (p === "/bomb") { const b = zlib.gzipSync(Buffer.concat([Buffer.from("{"), Buffer.alloc(5_000_000, " "), Buffer.from("}")])); resp.writeHead(200, { "content-encoding": "gzip", "content-length": b.length }); resp.end(b); }
  else if (p === "/gz") { const b = zlib.gzipSync(Buffer.from(dirPub)); resp.writeHead(200, { "content-encoding": "gzip", "content-type": W.MEDIA_TYPE, "content-length": b.length }); resp.end(b); }
  else if (p === "/br") { resp.writeHead(200, { "content-encoding": "br", "content-length": 2 }); resp.end("{}"); }
  else if (p === "/redirect") { resp.writeHead(302, { location: "https://localhost/target", "content-length": 0 }); resp.end(); }
  else if (p === "/target") { targetHits++; resp.writeHead(200, { "content-length": 2 }); resp.end("{}"); }
  else if (p === "/slow") {
    resp.writeHead(200, { "content-length": 60000 });
    let n = 0; const t = setInterval(() => { if (n++ > 50 || resp.destroyed) { clearInterval(t); return; } resp.write("xxxxxxxxxx"); }, 200);
  }
});
await new Promise((s) => srv.listen(0, "127.0.0.1", s));
const L = `https://localhost:${srv.address().port}`;
try {
  check("loopback refused even for the test server unless allowPrivate", (await refused(L + "/gz", { ca: CA })) !== null);
  const [st, , bd] = await W.httpsGet(L + "/gz", { allowPrivate: true, ca: CA });
  check("gzip key list decoded", st === 200 && JSON.parse(new TextDecoder().decode(bd)).keys[0].x === PUB.x, st);
  let why = await refused(L + "/big", { allowPrivate: true, ca: CA });
  check("200 kB body over the 64 kB cap refused", why && why.includes("larger"), why);
  why = await refused(L + "/bigchunked", { allowPrivate: true, ca: CA });
  check("200 kB chunked body over the cap refused", why && why.includes("larger"), why);
  let t0 = Date.now(); why = await refused(L + "/bomb", { allowPrivate: true, ca: CA });
  check("gzip bomb (5 MB inflated) refused at 64 kB", why && why.includes("larger") && Date.now() - t0 < 3000, why);
  why = await refused(L + "/br", { allowPrivate: true, ca: CA });
  check("unsupported content-encoding refused", why && why.includes("content-encoding"), why);
  const [st2] = await W.httpsGet(L + "/redirect", { allowPrivate: true, ca: CA });
  check("302 returned as is, not followed", st2 === 302 && targetHits === 0, [st2, targetHits]);
  t0 = Date.now(); why = await refused(L + "/slow", { allowPrivate: true, ca: CA, timeout: 1 });
  const dt = Date.now() - t0;
  check("slow body (slowloris) stopped by the wall-clock timeout", why && why.includes("timed out") && dt < 2000, [why, dt]);
  why = await refused(L + "/gz", { allowPrivate: true });
  check("untrusted certificate refused", why && why.includes("TLS"), why);
} finally { srv.close(); srv.closeAllConnections?.(); fs.rmSync(td, { recursive: true, force: true }); }
if (LIVE) {
  const why = await refused("https://self-signed.badssl.com/");
  check("bad TLS certificate refused (live)", why && why.includes("TLS"), why);
  const [st] = await W.httpsGet("https://google.com/");
  check("real redirect (google.com 301) not followed", st === 301 || st === 302, st);
}

// ═════════════ 7. request objects ═════════════
section("7 request objects");
const f7 = new Fake({ [dirUrl(AG)]: [200, DIR_HDRS, dirPub] });
const V7 = new W.Verifier({ fetch: f7.fn });
r = await V7.verify(new Request(url, { headers: await signed() }));
check("Fetch Request -> verified", r.verified, show(r));
r = await V7.verify(new Request(url, { method: "POST", headers: await signed() }));
check("Fetch Request: signed GET replayed as POST -> invalid", r.outcome === W.INVALID, show(r));
const site = http.createServer(async (req, resp) => {
  const out = await V7.verify(req, { publicBaseUrl: "https://shop.example" });
  resp.writeHead(200, { "content-type": "application/json" }); resp.end(JSON.stringify(out));
});
await new Promise((s) => site.listen(0, "127.0.0.1", s));
const SP = site.address().port;
const nodeCall = (p, method, hd) => new Promise((ok_, bad) => {
  const q = http.request({ host: "127.0.0.1", port: SP, path: p, method, headers: hd }, (res2) => {
    let b = ""; res2.on("data", (c) => (b += c)); res2.on("end", () => ok_(JSON.parse(b)));
  });
  q.on("error", bad); q.end();
});
try {
  for (const u of ["https://shop.example/p/1?colour=blue", "https://shop.example/a%20b/c%2Fd?q=a+b&x=%C3%A9", "https://shop.example/"]) {
    const p = u.replace("https://shop.example", "");
    const out = await nodeCall(p, "GET", await W.signRequest(KEY, "GET", u, AG));
    check(`node:http request ${p} -> verified (raw path kept, %2F intact)`, out.outcome === "verified", out);
  }
  const out = await nodeCall("/p/1", "POST", await W.signRequest(KEY, "GET", "https://shop.example/p/1", AG));
  check("node:http: signed GET replayed as POST -> invalid", out.outcome === "invalid", out);
  const out2 = await V7.verify({ method: "GET", url: "/p/1", headers: { host: "shop.example", ...(await W.signRequest(KEY, "GET", "https://shop.example/p/1", AG)) }, socket: { encrypted: true } });
  check("Express-style req without publicBaseUrl: origin from Host + TLS socket", out2.verified, show(out2));
  const out3 = await V7.verify({ method: "GET", url: "/p/1", headers: {} });
  check("relative URL, no Host, no publicBaseUrl -> unverified, not a crash", out3.outcome === W.UNVERIFIED, show(out3));
} finally { site.close(); }

// ═════════════ 8. live ═════════════
if (LIVE && fs.existsSync(PY)) {
  section("8 live key lists");
  const VL = new W.Verifier();
  try {
    const info = await VL.resolve("https://chatgpt.com");
    check("chatgpt.com key list resolves (foreign directory)", info.keys.length && !info.stale, info);
    check("chatgpt.com key carries a valid domain proof (Appendix B)", JSON.stringify(info.domainProof) === JSON.stringify(info.keys), info);
  } catch (e) { check("chatgpt.com key list resolves", false, e.message); }
  r = await VL.verify(null, { method: "GET", url, headers: await W.signRequest(KEY, "GET", url, "https://chatgpt.com") });
  check("our key claiming chatgpt.com -> unverified, not attributed", r.outcome === W.UNVERIFIED && r.agent === null, show(r));
  const CF = "https://http-message-signatures-example.research.cloudflare.com";
  try {
    const info = await VL.resolve(CF);
    check("Cloudflare demo list resolves; its key is flagged as the RFC test key", JSON.stringify(info.testKeys) === JSON.stringify([ED_THUMB]), info);
  } catch (e) { check("Cloudflare demo list resolves", false, e.message); }
  r = await VL.verify(null, { method: "GET", url, headers: await W.signRequest(ED_KEY, "GET", url, CF) });
  check("request signed with that public test key -> invalid (6.8)", r.outcome === W.INVALID && r.reason.includes("test key"), show(r));
  r = await new W.Verifier({ allowTestKeys: true }).verify(null, { method: "GET", url, headers: await W.signRequest(ED_KEY, "GET", url, CF) });
  check("... verified when test keys are allowed (Cloudflare's live list)", r.verified && r.agent === CF + W.WELL_KNOWN, show(r));

  // a throwaway agent on authyouragent.com publishes a JS-made key; sign; verify; revoke
  const KEYF = path.join(os.tmpdir(), `wbajs-${process.pid}.json`);
  const k = await W.newKey();
  const kp = await W.publicJwk(k);
  const priv = await crypto.subtle.exportKey("jwk", k.privateKey);
  fs.writeFileSync(KEYF, JSON.stringify({ pub: kp, d: priv.d }), { mode: 0o600 });
  try {
    const out = JSON.parse(execFileSync(PY, [path.join(HERE, "live_agent_js.py"), "up", KEYF], { encoding: "utf8" }));
    check("throwaway agent published on authyouragent.com (directory signed by the JS key)", out.ok, out);
    const VA = new W.Verifier();
    r = await VA.verify(null, { method: "GET", url, headers: await W.signRequest(k, "GET", url, out.signature_agent) });
    check("our live agent verifies via its live directory", r.verified && r.agent === out.signature_agent + W.WELL_KNOWN, show(r));
    check("... with the domain proof (Appendix B)", r.domainProof === true, show(r));
    execFileSync(PY, [path.join(HERE, "live_agent_js.py"), "revoke", KEYF], { encoding: "utf8" });
    r = await new W.Verifier().verify(null, { method: "GET", url, headers: await W.signRequest(k, "GET", url, out.signature_agent) });
    check("after revoke, a fresh verifier refuses it (empty key list)", r.outcome === W.UNVERIFIED && r.reason.includes("does not hold"), show(r));
    const held = VA._cache.get(out.signature_agent + W.WELL_KNOWN);
    check(`the verifier that had it cached keeps it for at most the list's max-age (${held.freshUntil - held.fetched} s)`, held.freshUntil - held.fetched <= 300);
  } finally {
    try { execFileSync(PY, [path.join(HERE, "live_agent_js.py"), "delete", KEYF], { encoding: "utf8" }); } catch (e) { console.log("  cleanup:", e.message); }
    fs.rmSync(KEYF, { force: true });
  }
}

console.log(`\n${ok.filter(Boolean).length}/${ok.length} passed`);
process.exit(ok.every(Boolean) ? 0 : 1);
