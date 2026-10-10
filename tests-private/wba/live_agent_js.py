"""Throwaway agent on authyouragent.com for verify_test.mjs section 8.

  live_agent_js.py up KEYFILE      account + agent, publish the JS-made Ed25519 key, print {ok, signature_agent}
  live_agent_js.py revoke KEYFILE  revoke the agent (its directory becomes {"keys":[]})
  live_agent_js.py delete KEYFILE  delete the throwaway account

KEYFILE (mode 600, made by the JS test) holds {pub, d}; this script adds its own state to it.
"""
import base64, json, sys, time
sys.path.insert(0, "/root/authyouragent/sdk")
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authyouragent import webbotauth as W
from authyouragent.agent import AgentClient, keygen, agent_jwk

CLOUD = "https://authyouragent.com"
PW = "hunter2hunter"
cmd, path = sys.argv[1], sys.argv[2]
st = json.load(open(path))


def save():
    with open(path, "w") as f:
        json.dump(st, f)


def owner():
    return httpx.Client(base_url=CLOUD, timeout=30, cookies={"authyouragent_session": st["session"]}, headers={"Origin": CLOUD})


if cmd == "up":
    c = httpx.Client(base_url=CLOUD, timeout=30, headers={"Origin": CLOUD})
    st["email"] = f"wbaverifyjs+{int(time.time())}@example.com"
    c.post("/api/users", json={"email": st["email"], "password": PW, "display_name": "Test"})
    st["session"] = c.post("/api/login", json={"email": st["email"], "password": PW}).cookies.get("authyouragent_session")
    save()
    priv, pub = keygen()
    st["aid"] = owner().post("/api/agents", json={"name": "Probe JS", "jwk": agent_jwk(pub)}).json()["id"]
    save()
    a = AgentClient(base_url=CLOUD, agent_id=st["aid"], privkey_pem=priv)
    k = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(st["d"] + "=" * (-len(st["d"]) % 4)))
    assert W.public_jwk(k)["x"] == st["pub"]["x"]
    inf = httpx.post(CLOUD + "/api/v1/wba/key", json={"agent_id": st["aid"], "agent_jwt": a._agent_jwt(), "jwk": st["pub"]}).json()
    rr = httpx.post(CLOUD + "/api/v1/wba/proof", json={"agent_id": st["aid"], "agent_jwt": a._agent_jwt(),
                    "headers": W.sign_directory(k, inf["directory"].encode(), inf["host"])})
    print(json.dumps({"ok": rr.status_code == 200, "signature_agent": inf["signature_agent"], "detail": rr.text[:120]}))
elif cmd == "revoke":
    owner().post(f"/api/agents/{st['aid']}/flag", json={"flag": "revoked"})
elif cmd == "delete":
    if st.get("session"):
        owner().post("/api/account/delete", json={"password": PW, "confirm": st["email"]})
