"""Cross-SDK check: a Python agent calling a site that verifies with the JS SDK
(local mode), and a JS agent's DPoP proof verified by the Python SiteVerifier
(local mode). Proves both SDKs speak standard JWS (raw r||s) and that the
Python site still accepts old DER-signed proofs."""
import json, os, subprocess, sys, time, threading
import httpx

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "sdk"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from authyouragent import AgentClient, SiteVerifier, AuthError, keygen, agent_jwk  # noqa
import phone_helper as ph  # noqa

CLOUD = os.environ["CLOUD"]
res = []
def check(n, ok, extra=""):
    res.append(ok); print("PASS" if ok else "FAIL", n, "" if ok else extra)

priv, pub = keygen()
import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    ph.setup(json.dumps(agent_jwk(pub)))
acct = json.loads(buf.getvalue())
agent = AgentClient(base_url=CLOUD, agent_id=acct["agent_id"], privkey_pem=priv, verify=False)
SITE = "127.0.0.1"
t = threading.Thread(target=lambda: ph.approve(acct["session"], "initial")); t.start()
agent.ensure_grant(SITE, ["list"]); t.join()

# 1. Python agent -> JS site (local mode)
url = "http://127.0.0.1:1/api/jobs"
at = agent._get_access(SITE)
proof = agent._dpop_proof("GET", url, at)
js = r"""
import { SiteVerifier } from "%s/sdk-js/src/index.js";
const v = new SiteVerifier({ baseUrl: process.env.CLOUD, expectedAudience: "127.0.0.1", mode: "local" });
const [at, dpop, url] = process.argv.slice(1);
try { const a = await v.verify({ method: "GET", url, headers: { authorization: "Bearer " + at, dpop } }, { url });
      console.log(JSON.stringify({ ok: true, agent: a.agentId })); }
catch (e) { console.log(JSON.stringify({ ok: false, error: e.message })); }
""" % BASE
out = subprocess.run(["node", "--input-type=module", "-e", js, at, proof, url], capture_output=True, text=True,
                     env={**os.environ, "NODE_TLS_REJECT_UNAUTHORIZED": "0"})
d = json.loads(out.stdout.strip().splitlines()[-1]) if out.stdout.strip() else {"ok": False, "error": out.stderr[-300:]}
check("Python agent proof accepted by JS site (local)", d.get("ok") and d.get("agent") == acct["agent_id"], str(d))

# 2. JS-style proof (raw r||s) and legacy DER proof, both at the Python site (local)
class R:
    def __init__(self, proof):
        self.method = "GET"; self.url = url
        self.headers = {"authorization": f"Bearer {at}", "dpop": proof}
v = SiteVerifier(CLOUD, verify=False, mode="local", expected_audience=SITE, public_base_url="http://127.0.0.1:1")
p2 = agent._dpop_proof("GET", url, at)
check("raw r||s proof accepted by Python site (local)", v.verify(R(p2)).agent_id == acct["agent_id"])
# legacy DER-signed proof, as SDK <= 0.2 produced
import base64, json as _j, hashlib as _h
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
h, p, _ = agent._dpop_proof("GET", url, at).split(".")
pl = _j.loads(base64.urlsafe_b64decode(p + "=="))
pl["jti"] = "j_legacy" + str(time.time_ns())[-8:]
p = base64.urlsafe_b64encode(_j.dumps(pl, separators=(",", ":")).encode()).rstrip(b"=").decode()
der = agent.key.sign((h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
legacy = h + "." + p + "." + base64.urlsafe_b64encode(der).rstrip(b"=").decode()
check("legacy DER proof still accepted by Python site", v.verify(R(legacy)).agent_id == acct["agent_id"])
check("raw proof accepted by the cloud verify", httpx.post(CLOUD + "/api/v1/verify", verify=False, json={
    "access_token": at, "dpop": agent._dpop_proof("GET", url, at), "method": "GET", "url": url}).json().get("valid") is True)
print("RESULT: %d/%d interop checks passed" % (sum(res), len(res)))
sys.exit(0 if all(res) else 1)
