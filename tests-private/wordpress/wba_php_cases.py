"""Write the cases for wba_php_test.php: signatures from the Python SDK, the JS
SDK and Cloudflare's npm web-bot-auth signer, the RFC 9421 / draft vectors,
refusals and cache sequences, each with the outcome the SDK verifiers give.
Usage: .venv/bin/python tests-private/wordpress/wba_php_cases.py OUT.json"""
import base64, json, os, subprocess, sys, time
sys.path.insert(0, "/root/authyouragent/sdk")
sys.path.insert(0, "/root/authyouragent/tests-private/wba")
from authyouragent import webbotauth as W
from authyouragent import _sfv as sfv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
WBA = os.path.join(os.path.dirname(HERE), "wba")
KEYS = "/root/.hermes/cache/scratch/wbagh/examples/rfc9421-keys"
b64 = lambda b: base64.b64encode(b).decode()
DIR_H = {"content-type": W.MEDIA_TYPE, "cache-control": "max-age=300"}
dir_url = lambda o: o.rstrip("/") + W.WELL_KNOWN


def directory(*jwks):
    keys = [dict(j, kid=W.thumbprint(j)) if j.get("kty") == "OKP" else dict(j) for j in jwks]
    return json.dumps({"keys": keys}).encode()


def route(status, hdrs, body):
    return [status, hdrs, b64(body)]


def unwrap(s):
    out = ""
    for ln in s.strip("\n").split("\n"):
        out = (out[:-1] + ln.lstrip()) if out.endswith("\\") else (out + ("\n" if out else "") + ln)
    return out


ed = json.load(open(f"{KEYS}/ed25519.json"))
ED_PUB = {"kty": "OKP", "crv": "Ed25519", "x": ed["x"]}
ED_KEY = Ed25519PrivateKey.from_private_bytes(W._unb64u(ed["d"]))
rsa = json.load(open(f"{KEYS}/rsapss.json"))
RSA_PUB = {"kty": "RSA", "n": rsa["n"], "e": rsa["e"], "alg": "PS512"}
cases = {"bvec": [], "sfv": [], "verify": []}

# ── RFC 9421 Appendix B ──
BH = {"Host": "example.com", "Date": "Tue, 20 Apr 2021 02:07:55 GMT", "Content-Type": "application/json",
      "Content-Digest": "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      "Content-Length": "18"}
src = open(os.path.join(WBA, "verify_test.py")).read()
cases["bvec"] = [
    {"name": "B.2.6 ed25519 base rebuilt, published signature verifies", "headers": BH, "jwk": ED_PUB, "alg": "ed25519",
     "si": unwrap('''sig-b26=("date" "@method" "@path" "@authority" \\
  "content-type" "content-length");created=1618884473\\
  ;keyid="test-key-ed25519"'''), "sig": "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="},
    {"name": "B.2.2 rsa-pss-sha512 with @query-param + content-digest", "headers": BH, "jwk": RSA_PUB, "alg": "rsa-pss-sha512",
     "si": unwrap('''sig-b22=("@authority" "content-digest" \\
  "@query-param";name="Pet");created=1618884473\\
  ;keyid="test-key-rsa-pss";tag="header-example"'''),
     "sig": unwrap('''LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ\\
  EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT\\
  8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA\\
  RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd\\
  4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK\\
  UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==''')},
    {"name": "B.2.3 full coverage incl. @query (rsa-pss-sha512)", "headers": BH, "jwk": RSA_PUB, "alg": "rsa-pss-sha512",
     "si": unwrap('''sig-b23=("date" "@method" "@path" "@query" \\
  "@authority" "content-type" "content-digest" "content-length")\\
  ;created=1618884473;keyid="test-key-rsa-pss"'''),
     "sig": unwrap('''bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB\\
  iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU\\
  xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1\\
  pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9\\
  bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z\\
  JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==''')},
]
cases["sfv"] = ['sig2=("@authority" "signature-agent";key="agent2");created=1;keyid="k";tag="web-bot-auth"',
                "a=1, b=?0, d=:QQ==:, e=1.5, f=tok-1, g=(-5.25)"]

V = cases["verify"]
def add(name, method, url, headers, routes, expect, opts=None, now=None):
    V.append({"name": name, "method": method, "url": url, "headers": headers, "routes": routes, "expect": expect,
              "opts": opts or {}, "now": now})

# ── draft Appendix E (copied from verify_test.py) ──
ns = {}
start, end = src.index("E = {"), src.index("for name, (agent, si_, sg_) in E.items():")
exec(src[start:end], {"unwrap": unwrap}, ns)
TA = "https://signature-agent.test"
vec_routes = {dir_url(TA): route(200, DIR_H, directory(ED_PUB, RSA_PUB))}
for name, (agent, si, sg) in ns["E"].items():
    h = {"Signature-Agent": agent, "Signature-Input": si, "Signature": sg}
    add(f"{name}: verified, agent = well-known URL", "GET", "https://example.com/", h, vec_routes,
        {"outcome": "verified", "agent": dir_url(TA)}, {"allow_test_keys": True, "max_lifetime": None}, 1735690000)
    add(f"{name}: refused for another authority", "GET", "https://example.org/", h, vec_routes,
        {"outcome": "invalid"}, {"allow_test_keys": True, "max_lifetime": None}, 1735690000)
e21 = dict(zip(("Signature-Agent", "Signature-Input", "Signature"), ns["E"]["E.2.1 ed25519, dictionary Signature-Agent"]))
add("draft 6.8: the RFC test key is refused by default", "GET", "https://example.com/", e21, vec_routes,
    {"outcome": "invalid", "reason": "test key"}, {"max_lifetime": None}, 1735690000)
add("a 99-year signature is refused by default (24 h)", "GET", "https://example.com/", e21, vec_routes,
    {"outcome": "invalid", "reason": "more than"}, {"allow_test_keys": True}, 1735690000)
s = src[src.index("E23_BODY ="):src.index("kl = W._parse_list(200, E23_HDRS")]
e23 = {}
exec(s, {"DIR_HDRS": DIR_H}, e23)
cases["e23"] = {"headers": e23["E23_HDRS"], "body": e23["E23_BODY"].decode()}

# ── interop ──
AG = "https://agent.example"
KEY = W.new_key(); PUB = W.public_jwk(KEY)
url = "https://shop.example/p/1?colour=blue"
R = {dir_url(AG): route(200, DIR_H, directory(PUB))}
add("Python SDK signer -> verified, agent = well-known URL", "GET", url, W.sign_request(KEY, "GET", url, AG), R,
    {"outcome": "verified", "agent": dir_url(AG), "label": "sig1"})
js = json.loads(subprocess.run(["node", "--input-type=module", "-e", f"""
import * as W from "/root/authyouragent/sdk-js/src/webbotauth.js";
const k = await W.newKey();
console.log(JSON.stringify({{ jwk: await W.publicJwk(k), headers: await W.signRequest(k, "GET", "{url}", "{AG}") }}));"""],
    capture_output=True, text=True, check=True).stdout)
add("JS SDK signer -> verified", "GET", url, js["headers"], {dir_url(AG): route(200, DIR_H, directory(js["jwk"]))}, {"outcome": "verified"})
cf = subprocess.run(["node", "cf_sign.mjs"], cwd=WBA, capture_output=True, text=True,
                    input=json.dumps({"url": url, "method": "GET", "agent": f'sig1="{AG}"'}))
if cf.returncode == 0:
    cf = json.loads(cf.stdout)
    RC = {dir_url(AG): route(200, DIR_H, directory(cf["jwk"]))}
    add("Cloudflare-signed request (dictionary form) -> verified", "GET", url, cf["headers"], RC, {"outcome": "verified"})
    add("Cloudflare signs @authority only: another path/method still verifies", "POST", "https://shop.example/other", cf["headers"], RC, {"outcome": "verified"})

# ── refusals ──
NOW = int(time.time())
sg = lambda **k: W.sign_request(k.get("key", KEY), k.get("method", "GET"), k.get("url", url), k.get("agent", AG), now=k.get("now"))
add("other path -> invalid", "GET", "https://shop.example/p/2", sg(), R, {"outcome": "invalid"})
add("other method -> invalid", "POST", url, sg(), R, {"outcome": "invalid"})
add("other host -> invalid", "GET", "https://evil.example/p/1", sg(), R, {"outcome": "invalid"})
add("expired -> invalid", "GET", url, sg(now=NOW - 1000), R, {"outcome": "invalid", "reason": "expired"})
add("created in the future -> invalid", "GET", url, sg(now=NOW + 1000), R, {"outcome": "invalid", "reason": "future"})
h = sg(); h["Signature"] = h["Signature"][:10] + ("A" if h["Signature"][10] != "A" else "B") + h["Signature"][11:]
add("altered signature bytes -> invalid", "GET", url, h, R, {"outcome": "invalid"})
R2 = dict(R); R2[dir_url("https://other.example")] = route(200, DIR_H, directory(PUB))
h = sg(); h["Signature-Agent"] = '"https://other.example"'
add("swapped Signature-Agent (covered) -> invalid, not attributed", "GET", url, h, R2, {"outcome": "invalid", "agent": None})
OTHER = W.new_key()
add("key not in the agent's list -> unverified", "GET", url, sg(key=OTHER), R, {"outcome": "unverified", "reason": "does not hold"})
VICTIM = "https://victim.example"
R3 = dict(R); R3[dir_url(VICTIM)] = route(200, DIR_H, directory(W.public_jwk(W.new_key())))
add("5.4 pair rule: AG's key claiming VICTIM -> unverified, not attributed", "GET", url, sg(agent=VICTIM), R3, {"outcome": "unverified", "agent": None})
for bad_agent, why in (("http://agent.example", "http"), ("https://agent.example/keys", "path"), ("https://agent.example?x=1", "query"),
                       ("https://user@agent.example", "userinfo"), ("https://agent.example:99999", "port")):
    add(f"Signature-Agent with {why} -> unverified, no fetch", "GET", url, sg(agent=bad_agent), R, {"outcome": "unverified", "calls": 0})
P = lambda **kw: dict({"created": NOW, "expires": NOW + 300, "keyid": W.thumbprint(PUB), "alg": "ed25519", "tag": "web-bot-auth"}, **kw)


def custom(components, params, agent_hdr, key=KEY, label="sig1", u=url, method="GET", sign_hdr=None):
    member = ([(c, p) for c, p in components], params)
    hdr = sign_hdr or agent_hdr
    base = W._Msg(method, u, {"Signature-Agent": hdr} if hdr else {}).base([(c, dict(p)) for c, p in components], member)
    out = {"Signature-Input": f"{label}={sfv.ser_member(member)}", "Signature": f"{label}=:{b64(key.sign(base))}:"}
    if agent_hdr:
        out["Signature-Agent"] = agent_hdr
    return out


A = f'"{AG}"'
add("does not cover Signature-Agent -> unverified", "GET", url, custom([("@authority", {})], P(), A), R, {"outcome": "unverified"})
add("covers neither @authority nor @target-uri -> invalid", "GET", url, custom([("@path", {}), ("signature-agent", {})], P(), A), R, {"outcome": "invalid"})
add("@target-uri + dictionary member -> verified", "GET", url, custom([("@target-uri", {}), ("signature-agent", {"key": "sig1"})], P(), f'sig1="{AG}"'), R, {"outcome": "verified"})
add("@target-uri: changed query -> invalid", "GET", url + "&x=2", custom([("@target-uri", {}), ("signature-agent", {"key": "sig1"})], P(), f'sig1="{AG}"'), R, {"outcome": "invalid"})
add("hmac-sha256 -> invalid (6.4)", "GET", url, custom([("@authority", {}), ("signature-agent", {})], P(alg="hmac-sha256"), A), R, {"outcome": "invalid", "reason": "shared"})
add("alg not matching the key -> invalid", "GET", url, custom([("@authority", {}), ("signature-agent", {})], P(alg="rsa-pss-sha512"), A), R, {"outcome": "invalid"})
add("no expires -> invalid", "GET", url, custom([("@authority", {}), ("signature-agent", {})], {k: v for k, v in P().items() if k != "expires"}, A), R, {"outcome": "invalid"})
add("no keyid -> invalid", "GET", url, custom([("@authority", {}), ("signature-agent", {})], {k: v for k, v in P().items() if k != "keyid"}, A), R, {"outcome": "invalid"})
add("tag other than web-bot-auth -> unsigned", "GET", url, custom([("@authority", {}), ("signature-agent", {})], P(tag="other"), A), R, {"outcome": "unsigned"})
add("no headers -> unsigned", "GET", url, {}, R, {"outcome": "unsigned"})
add("garbled Signature-Input -> invalid", "GET", url, {"Signature-Input": "sig1=(", "Signature": "sig1=:AA==:"}, R, {"outcome": "invalid"})
add("covers two Signature-Agent members -> unverified", "GET", url,
    custom([("@authority", {}), ("signature-agent", {"key": "a"}), ("signature-agent", {"key": "b"})], P(), f'a="{AG}", b="{VICTIM}"'), R, {"outcome": "unverified"})
BOTH = f's1="{AG}", s2="{AG}"'
good = custom([("@authority", {}), ("signature-agent", {"key": "s2"})], P(), None, label="s2", sign_hdr=BOTH)
badh = custom([("@authority", {}), ("signature-agent", {"key": "s1"})], P(keyid=W.thumbprint(W.public_jwk(OTHER))), None, key=OTHER, label="s1", sign_hdr=BOTH)
add("two signatures, one unknown key + one good -> verified, other listed", "GET", url,
    {"Signature-Agent": BOTH, "Signature-Input": badh["Signature-Input"] + ", " + good["Signature-Input"], "Signature": badh["Signature"] + ", " + good["Signature"]},
    R, {"outcome": "verified", "label": "s2", "others": 1})
one = lambda j: json.dumps({"keys": [j]}).encode()
for host, entry, label in (("kid", dict(PUB, kid="label-1"), "directory kid not the thumbprint -> key ignored"),
                           ("exp", dict(PUB, exp=NOW - 10), "key past its exp -> ignored"),
                           ("priv", dict(PUB, d="AAAA"), "entry carrying a private key -> ignored")):
    add(label, "GET", url, sg(agent=f"https://{host}.example"), {dir_url(f"https://{host}.example"): route(200, DIR_H, one(entry))}, {"outcome": "unverified"})
add("directory with the wrong media type -> unverified", "GET", url, sg(agent="https://ctype.example"),
    {dir_url("https://ctype.example"): route(200, {"content-type": "application/json"}, directory(PUB))}, {"outcome": "unverified", "reason": "served as"})
add("more than 32 keys -> unverified", "GET", url, sg(agent="https://many.example"),
    {dir_url("https://many.example"): route(200, DIR_H, directory(*[W.public_jwk(W.new_key()) for _ in range(40)], PUB))}, {"outcome": "unverified", "reason": "more than"})
add("redirect answer -> unverified, not followed", "GET", url, sg(agent="https://redir.example"),
    {dir_url("https://redir.example"): route(302, {"location": dir_url(AG)}, b"")}, {"outcome": "unverified", "reason": "302"})
add("type=jwks_uri: verified, identifier drops the query, operator kid allowed", "GET", url,
    custom([("@authority", {}), ("signature-agent", {"key": "sig1"})], P(), 'sig1="https://jw.example/keys.json?v=1";type=jwks_uri'),
    {"https://jw.example/keys.json?v=1": route(200, {"content-type": "application/json"}, one(dict(PUB, kid="my-label")))},
    {"outcome": "verified", "agent": "https://jw.example/keys.json"})
add("domain proof reported for a signed directory", "GET", url, sg(agent="https://proof.example"),
    {dir_url("https://proof.example"): route(200, dict(DIR_H, **{k.lower(): v for k, v in W.sign_directory(KEY, directory(PUB), "proof.example").items()}), directory(PUB))},
    {"outcome": "verified", "domain_proof": True})

# ── cache sequences ──
MA = lambda n: {"content-type": W.MEDIA_TYPE, "cache-control": f"max-age={n}"}
st = lambda now, expect, key=KEY, routes=None: dict({"method": "GET", "url": url, "headers": W.sign_request(key, "GET", url, AG, now=now), "now": now, "expect": expect},
                                                     **({"routes": routes} if routes else {}))
RA = {dir_url(AG): route(200, MA(600), directory(PUB))}
V.append({"name": "max-age 600: five requests one fetch; refetched after; removed key stops verifying", "routes": RA, "steps":
          [st(NOW + i, {"outcome": "verified", "calls": 1}) for i in range(5)] +
          [st(NOW + 700, {"outcome": "verified", "calls": 2}),
           st(NOW + 1400, {"outcome": "unverified", "calls": 3}, routes={dir_url(AG): route(200, MA(600), directory(W.public_jwk(W.new_key())))})]})
RB = {dir_url(AG): route(200, MA(60), directory(PUB))}
V.append({"name": "outage: old copy used (stale), negative cache, refused after max_stale", "routes": RB, "steps":
          [st(NOW, {"outcome": "verified", "calls": 1}),
           st(NOW + 120, {"outcome": "verified", "stale": True, "calls": 2}, routes={dir_url(AG): "connection refused"}),
           st(NOW + 130, {"outcome": "verified", "stale": True, "calls": 2}),
           st(NOW + 90000, {"outcome": "unverified"})]})
V.append({"name": "first fetch fails (HTTP 500): unverified", "routes": {dir_url(AG): route(500, {}, b"")}, "steps": [st(NOW, {"outcome": "unverified", "reason": "500"})]})
RN = {dir_url(AG): route(200, {"content-type": W.MEDIA_TYPE, "cache-control": "no-store"}, directory(PUB))}
V.append({"name": "no-store: reused for min_ttl (one fetch for 3 requests)", "routes": RN, "steps": [st(NOW + i, {"outcome": "verified", "calls": 1}) for i in range(3)]})
V.append({"name": "no-store with min_ttl=0: fetched every time", "routes": RN, "opts": {"min_ttl": 0},
          "steps": [st(NOW + i, {"outcome": "verified", "calls": i + 1}) for i in range(3)]})
NEW = W.new_key()
V.append({"name": "a key added later: refetched only after refetch_after", "routes": {dir_url(AG): route(200, MA(3600), directory(PUB))}, "steps": [
    st(NOW, {"outcome": "verified", "calls": 1}),
    st(NOW + 10, {"outcome": "unverified", "calls": 1}, key=NEW, routes={dir_url(AG): route(200, MA(3600), directory(PUB, W.public_jwk(NEW)))}),
    st(NOW + 120, {"outcome": "verified", "calls": 2}, key=NEW)]})

json.dump(cases, open(sys.argv[1], "w"))
print(len(cases["bvec"]), "vectors,", len(V), "verify cases")
