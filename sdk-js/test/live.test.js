// Live end-to-end test of the JS SDK against a running Auth Your Agent cloud.
//
//   CLOUD=https://… PHONE_HELPER=/path/approve.py node --test test/
//
// The "site" is a local Node HTTP server using SiteVerifier; the agent uses
// AgentClient. The person's approvals are done by a Python helper that drives
// the real approval API with a software passkey (the same one the Python
// suites use), so every server check runs for real.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { AgentClient, SiteVerifier, AuthError, keygen } from "../src/index.js";

const CLOUD = process.env.CLOUD;
const HELPER = process.env.PHONE_HELPER;
const PY = process.env.PYTHON || "python3";
const SITE = process.env.SITE_ID || "127.0.0.1";
const skip = !CLOUD || !HELPER;

function helper(...args) {
  return new Promise((resolve, reject) => execFile(PY, [HELPER, ...args], { encoding: "utf8" },
    (err, out, errOut) => err ? reject(new Error(errOut || err.message)) : resolve(JSON.parse(out))));
}

function startSite(verifier) {
  const server = http.createServer(async (req, res) => {
    const send = (code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    try {
      if (req.url === "/api/jobs" && req.method === "GET") {
        const a = await verifier.verify(req);
        if (!a.scopes.includes("list")) return send(403, { error: "insufficient_scope" });
        return send(200, { jobs: ["j1"], agent: a.agentId, user: a.userId, userInfo: a.userInfo });
      }
      if (req.url === "/api/jobs/j1/apply" && req.method === "POST") {
        const a = await verifier.verify(req, { action: "apply" });
        if (!a.scopes.includes("apply")) return send(403, { error: "insufficient_scope" });
        if (!a.stepup) return send(403, { error: "stepup_required" });
        return send(200, { applied: true });
      }
      send(404, { error: "not found" });
    } catch (e) {
      send(e instanceof AuthError ? 401 : 500, { error: e.message });
    }
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server)));
}

test("keygen produces a P-256 key pair", { skip }, async () => {
  const k = await keygen();
  assert.match(k.privateKeyPem, /BEGIN PRIVATE KEY/);
  assert.equal(k.jwk.kty, "EC");
  assert.equal(k.jwk.crv, "P-256");
});

for (const mode of ["cloud", "local"]) {
  test(`agent + site round trip (${mode} mode)`, { skip, timeout: 120000 }, async (t) => {
    const key = await keygen();
    const acct = await helper("setup", JSON.stringify(key.jwk));
    // the site id is the host the agent calls (127.0.0.1); the DPoP URL is
    // rebuilt from publicBaseUrl, set once the port is known
    const verifier = new SiteVerifier({ baseUrl: CLOUD, expectedAudience: SITE, mode });
    const site = await startSite(verifier);
    const base = `http://127.0.0.1:${site.address().port}`;
    verifier.publicBaseUrl = base;
    t.after(() => site.close());

    const agent = new AgentClient({ baseUrl: CLOUD, agentId: acct.agent_id, privateKeyPem: key.privateKeyPem,
                                    pollInterval: 500 });
    // person approves in the background as soon as the request appears
    const approve = helper("approve", acct.session, "initial");
    const ok = await agent.ensureGrant(SITE, ["list", "apply"], { userInfo: ["user:name"] });
    await approve;
    assert.equal(ok, true);

    let r = await agent.fetch(`${base}/api/jobs`);
    let b = await r.json();
    assert.equal(r.status, 200, JSON.stringify(b));
    assert.equal(b.agent, acct.agent_id);
    assert.equal(b.userInfo["user:name"], "JS Tester");

    // a request without a valid pass + key proof is refused
    r = await fetch(`${base}/api/jobs`, { headers: { authorization: "Bearer not-a-real-pass", dpop: "x.y.z" } });
    assert.equal(r.status, 401);

    // sensitive action without stepupAction -> 403 passed through
    r = await agent.fetch(`${base}/api/jobs/j1/apply`, { method: "POST" });
    assert.equal(r.status, 403);

    // with stepupAction -> phone asked, retried, accepted
    const approve2 = helper("approve", acct.session, "stepup");
    r = await agent.fetch(`${base}/api/jobs/j1/apply`, { method: "POST", stepupAction: "apply" });
    await approve2;
    b = await r.json();
    assert.equal(r.status, 200, JSON.stringify(b));
    assert.equal(b.applied, true);

    // revoke -> refused (cloud: next request; local: after a revocation refresh)
    await helper("revoke", acct.session, acct.agent_id);
    // a fresh verifier = a site whose revocation list refreshed
    const v2 = new SiteVerifier({ baseUrl: CLOUD, expectedAudience: SITE, mode, publicBaseUrl: base });
    const pass = await agent._token(SITE).catch(() => null);
    const url = `${base}/api/jobs`;
    const fake = { method: "GET", url: "/api/jobs", headers: { authorization: `Bearer ${pass}`,
                   dpop: await agent.dpopProof("GET", url, pass) } };
    await assert.rejects(v2.verify(fake), (e) => e instanceof AuthError && /revoked/.test(e.error));
  });
}
