#!/usr/bin/env python3
"""Stand-in for the person's phone, for the JS SDK live tests.

  approve.py setup '<agent jwk json>'   -> {"session","agent_id"}  (new user + passkey + agent)
  approve.py approve <session> initial|stepup   waits for a pending request and approves it with the passkey
  approve.py revoke <session> <agent_id>        blocks the agent everywhere

The software passkey's private key is stored next to the session in a temp
file so later calls can sign assertions.
"""
import json, os, sys, time
import httpx

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
from test_softauth import SoftAuthenticator  # noqa: E402

CLOUD = os.environ["CLOUD"]
STATE = os.path.join(os.environ.get("TMPDIR", "/tmp"), "aya_js_phone_{}.json")


def save_phone(sess, phone):
    from cryptography.hazmat.primitives import serialization
    pem = phone.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode()
    with open(STATE.format(sess[:16]), "w") as f:
        json.dump({"pem": pem, "cred_id": phone.cred_id.hex(), "count": phone.sign_count,
                   "registered": phone._registered}, f)


def load_phone(sess):
    from cryptography.hazmat.primitives import serialization
    with open(STATE.format(sess[:16])) as f:
        d = json.load(f)
    phone = SoftAuthenticator(origin=CLOUD)
    phone.key = serialization.load_pem_private_key(d["pem"].encode(), password=None)
    phone.pub = phone.key.public_key()
    phone.cred_id = bytes.fromhex(d["cred_id"])
    phone.sign_count = d["count"]
    phone._registered = d["registered"]
    return phone


def client(session=None):
    c = httpx.Client(base_url=CLOUD, verify=False, timeout=30, headers={"Origin": CLOUD})
    if session:
        c.cookies.set("authyouragent_session", session)
    return c


def setup(jwk):
    email = f"jssdk+{int(time.time()*1000)}@example.test"
    c = client()
    r = c.post("/api/users", json={"email": email, "password": "hunter2hunter",
                                   "display_name": "JS Tester"})
    r.raise_for_status()
    sess = r.cookies.get("authyouragent_session")
    c = client(sess)
    phone = SoftAuthenticator(origin=CLOUD)
    d = c.get("/api/webauthn/register/options").json()
    c.post("/api/webauthn/register/verify",
           json={"challenge": "x", "attestation": phone.register(d["options"])}).raise_for_status()
    a = c.post("/api/agents", json={"name": "JS SDK agent", "jwk": json.loads(jwk)})
    a.raise_for_status()
    save_phone(sess, phone)
    print(json.dumps({"session": sess, "agent_id": a.json()["id"]}))


def approve(sess, kind):
    c = client(sess)
    phone = load_phone(sess)
    deadline = time.time() + 60
    while time.time() < deadline:
        pend = [t for t in c.get("/api/me").json()["pending"] if t["kind"] == kind]
        if pend:
            t = pend[0]
            opt = c.get(f"/api/txn/{t['id']}/assertion-options").json()
            r = c.post(f"/api/txn/{t['id']}/response",
                       json={"approve": True, "assertion": phone.get_assertion(opt["options"])})
            save_phone(sess, phone)
            print(json.dumps({"txn": t["id"], "status": r.status_code}))
            return
        time.sleep(0.5)
    print(json.dumps({"error": "no pending request"}))


def revoke(sess, agent_id):
    r = client(sess).post(f"/api/agents/{agent_id}/flag", json={"flag": "revoked"})
    print(json.dumps({"status": r.status_code}))


if __name__ == "__main__":
    cmd = sys.argv[1]
    {"setup": lambda: setup(sys.argv[2]),
     "approve": lambda: approve(sys.argv[2], sys.argv[3]),
     "revoke": lambda: revoke(sys.argv[2], sys.argv[3])}[cmd]()
