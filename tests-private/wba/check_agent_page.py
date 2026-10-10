"""/tools/check-agent (W3 3.5) against a running cloud.

Checks the plan's three cases (our live agent, OpenAI's chatgpt.com directory,
a broken signature) plus the other outcomes, request parsing, the JSON API,
escaping and the rate limit.
Usage: .venv/bin/python tests-private/wba/check_agent_page.py [CLOUD]   (default dev http://127.0.0.1:8440)
The live agent is a throwaway account on authyouragent.com (live_agent_js.py), deleted at the end.
"""
import base64, json, os, re, subprocess, sys, tempfile, time
sys.path.insert(0, "/root/authyouragent/sdk")
import httpx
from authyouragent import webbotauth as W
from cryptography.hazmat.primitives import serialization as ser

CLOUD = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8440"
HERE = os.path.dirname(os.path.abspath(__file__))
PY = "/root/authyouragent/.venv/bin/python"
c = httpx.Client(base_url=CLOUD, timeout=60)
ok = []


def check(name, cond, extra=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{str(extra)[:300]}]" if extra and not cond else ""))
    ok.append(bool(cond))


def verdict(h):
    m = re.search(r'class="verdict v-([a-z]+)"', h)
    return m.group(1) if m else ("error:" + (re.search(r'class="err">([^<]*)', h) or [None, "none"])[1])


def paste(method, url, headers, body_line=True, **extra):
    u = httpx.URL(url)
    lines = [f"{method} {u.raw_path.decode()} HTTP/1.1", f"Host: {u.host}"] + [f"{k}: {v}" for k, v in headers.items()]
    return "\n".join(lines)


def post(raw, **kw):
    return c.post("/tools/check-agent", data={"request": raw, **kw})


print("== page")
r = c.get("/tools/check-agent")
check("the empty page is indexable", 'content="noindex"' not in r.text)
check("page renders (200) with both forms", r.status_code == 200 and 'name="agent"' in r.text and 'name="request"' in r.text, r.status_code)
check("linked from sitemap and llms.txt", "/tools/check-agent" in c.get("/sitemap.xml").text and "/tools/check-agent" in c.get("/llms.txt").text)

print("== addresses")
r = c.get("/tools/check-agent", params={"agent": "chatgpt.com"})
check("chatgpt.com: key list found, key signed the list for its own address", verdict(r.text) == "found"
      and "signed the list for this address" in r.text, verdict(r.text))
check("result pages are noindex + no-store", 'name="robots" content="noindex"' in r.text and r.headers.get("cache-control") == "no-store",
      r.headers.get("cache-control"))
r = c.get("/tools/check-agent", params={"agent": "https://http-message-signatures-example.research.cloudflare.com"})
check("Cloudflare's demo list: its key is flagged as a published test key", "published RFC 9421 test key" in r.text, verdict(r.text))
for bad, why in (("https://127.0.0.1", "non-public"), ("http://example.com", "https"), ("https://example.com/keys", "origin")):
    r = c.get("/tools/check-agent", params={"agent": bad})
    check(f"address {bad}: not fetched, reason shown", verdict(r.text) == "unverified" and why in r.text, verdict(r.text))
r = c.get("/tools/check-agent", params={"agent": '"><script>alert(1)</script>'})
check("address input is escaped", "<script>alert(1)" not in r.text)

print("== requests")
KEY = W.new_key()
KEYF = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir=os.environ.get("TMPDIR")).name
os.chmod(KEYF, 0o600)
json.dump({"pub": W.public_jwk(KEY), "d": base64.urlsafe_b64encode(KEY.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw,
           ser.NoEncryption())).rstrip(b"=").decode()}, open(KEYF, "w"))
try:
    up = json.loads(subprocess.run([PY, os.path.join(HERE, "live_agent_js.py"), "up", KEYF], capture_output=True, text=True, check=True).stdout)
    check("throwaway agent published on authyouragent.com", up["ok"], up)
    AG = up["signature_agent"]
    url = "https://shop.example/products/42?colour=blue"
    h = W.sign_request(KEY, "GET", url, AG)
    r = post(paste("GET", url, h))
    check("our live agent's request: verified, address shown, Auth Your Agent named", verdict(r.text) == "verified"
          and AG in r.text and "Auth Your Agent: the agent" in r.text and "signed by this key for its own address" in r.text, verdict(r.text))
    r = post(paste("POST", url, h))
    check("same signature replayed as POST: invalid", verdict(r.text) == "invalid", verdict(r.text))
    bad = dict(h); bad["Signature"] = bad["Signature"][:12] + ("A" if bad["Signature"][12] != "A" else "B") + bad["Signature"][13:]
    r = post(paste("GET", url, bad))
    check("broken signature: invalid, 'does not verify'", verdict(r.text) == "invalid" and "does not verify" in r.text, verdict(r.text))
    old = W.sign_request(KEY, "GET", url, AG, now=int(time.time()) - 3600)
    r = post(paste("GET", url, old))
    check("an hour-old request: invalid (expired)", verdict(r.text) == "invalid" and "expired" in r.text, verdict(r.text))
    r = post(paste("GET", url, old), as_signed="1")
    check("... verified when checked as of when it was signed, and says so", verdict(r.text) == "verified"
          and "the moment it was signed" in r.text, verdict(r.text))
    r = post(paste("GET", url, W.sign_request(KEY, "GET", url, "https://chatgpt.com")))
    check("our key claiming chatgpt.com: not enough to decide, not attributed", verdict(r.text) == "unverified"
          and "does not hold" in r.text and "(not confirmed)" in r.text, verdict(r.text))
    r = post(paste("GET", url, {"User-Agent": "curl/8"}))
    check("no signature: unsigned", verdict(r.text) == "unsigned", verdict(r.text))
    raw = f"{url}\n" + "\n".join(f"{k}: {v}" for k, v in h.items())
    r = post(raw)
    check("absolute URL on the first line (no Host header) works", verdict(r.text) == "verified", verdict(r.text))
    raw = "\n".join(f"{k}: {v}" for k, v in h.items())
    r = post(raw)
    check("headers only, no Host: asks for the Host header", "Host header" in r.text, verdict(r.text))
    r = post("GET / HTTP/1.1\nHost: shop.example\nthis is not a header")
    check("a line that is not a header: plain error", "Not a header line" in r.text, verdict(r.text))
    r = post("GET / HTTP/1.1\nHost: shop.example\nX: " + "a" * 20000)
    check("over 16 kB: refused", "kB" in r.text and verdict(r.text).startswith("error"), verdict(r.text))
    r = post('GET /"><img src=x onerror=alert(1)> HTTP/1.1\nHost: shop.example\nSignature-Input: sig1=("@authority");tag="web-bot-auth"\nSignature: sig1=:AA==:')
    check("pasted text is escaped in the result", "<img src=x" not in r.text, verdict(r.text))

    print("== API")
    j = c.post("/api/v1/check-agent", json={"request": paste("GET", url, h)}).json()
    check("API request: verified, agent = key-list URL", j.get("outcome") == "verified" and j.get("agent") == AG + W.WELL_KNOWN and j.get("ours"), j)
    j = c.post("/api/v1/check-agent", json={"address": "https://chatgpt.com"}).json()
    check("API address: chatgpt.com found with keys", j.get("outcome") == "found" and j.get("keys"), j)
    r = c.post("/api/v1/check-agent", json={"address": "https://chatgpt.com", "request": "x"})
    check("API with both fields: 400", r.status_code == 400, r.status_code)
    subprocess.run([PY, os.path.join(HERE, "live_agent_js.py"), "revoke", KEYF], check=True)
    j = c.post("/api/v1/check-agent", json={"address": AG}).json()
    check("after revoke the address's key list is empty (fresh fetch, or cached up to its max-age)",
          j.get("outcome") == "found" and (j.get("keys") == [] or j.get("keys") == [W.thumbprint(W.public_jwk(KEY))]), j)
finally:
    subprocess.run([PY, os.path.join(HERE, "live_agent_js.py"), "delete", KEYF])
    os.unlink(KEYF)

if "--rate" in sys.argv:
    print("== rate limit")
    codes = [c.get("/tools/check-agent", params={"agent": "https://127.0.0.1"}).status_code for _ in range(35)]
    check("per-IP limit: 429 after 30 checks in 10 minutes, with a plain message", 429 in codes, codes)

print(f"\n{sum(ok)}/{len(ok)} passed")
sys.exit(0 if all(ok) else 1)
