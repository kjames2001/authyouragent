"""End-to-end: the Auth Your Agent WordPress plugin on a real WordPress +
WooCommerce, against the dev cloud.

Starts aya-wpp-db (MariaDB) and aya-wpp (WordPress, host network :8091),
installs WooCommerce + the plugin from integrations/wordpress/authyouragent,
registers an OIDC client for it, and checks:
  sign-in creates the agent's own account; a second sign-in reuses it;
  checkout asks the owner with the shop's words; denial blocks the order;
  approval places it, with a note; a changed basket needs a new confirmation;
  a forged/replayed logout token is refused; revoking ends the session.
Needs tests-private/selfhost/state.json (setup_owner.py) and the dev cloud.
Usage: python tests-private/wordpress/plugin_e2e.py [--keep]"""
import html, json, os, re, subprocess, sys, threading, time, httpx

ROOT = "/root/authyouragent"
HERE = os.path.dirname(os.path.abspath(__file__))
SH = os.path.join(ROOT, "tests-private", "selfhost")
S = json.load(open(os.path.join(SH, "state.json")))
WP = "http://localhost:8091"
PLUGIN = os.path.join(ROOT, "integrations", "wordpress", "authyouragent")
NET = "aya-wpp-net"

fails = 0
def check(name, ok, info=""):
    global fails
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(info)[:300]}"), flush=True)
    fails += 0 if ok else 1

def sh(cmd, check_rc=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check_rc and r.returncode:
        print(r.stdout[-800:], r.stderr[-800:]); raise SystemExit(f"command failed: {cmd[:120]}")
    return r.stdout.strip()

def wp(args):
    return sh(f"docker run --rm --network container:aya-wpp --volumes-from aya-wpp --user 33:33 "
              f"-e WORDPRESS_DB_HOST=127.0.0.1:3316 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp "
              f"wordpress:cli-php8.3 wp {args}")

# ------------------------------------------------------------------ containers
th = httpx.Client(base_url=S["cloud"], timeout=30, cookies={"authyouragent_session": S["session"]},
                  headers={"Origin": S["cloud"]})
if "wpplugin" not in S["clients"]:
    r = th.post("/api/oidc/clients", json={"name": "WordPress plugin test",
                "redirect_uris": [WP + "/wp-login.php?action=authyouragent_callback"],
                "backchannel_logout_uri": WP + "/wp-json/authyouragent/v1/backchannel-logout"})
    r.raise_for_status(); j = r.json()
    S["clients"]["wpplugin"] = {"client_id": j["client_id"], "client_secret": j["client_secret"]}
    json.dump(S, open(os.path.join(SH, "state.json"), "w"), indent=1)
CL = S["clients"]["wpplugin"]

if not sh("docker ps -q -f name=^aya-wpp$", False):
    sh("docker rm -f aya-wpp aya-wpp-db >/dev/null 2>&1; true", False)
    sh("docker run -d --name aya-wpp-db --network host -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD=wp "
       "-e MARIADB_RANDOM_ROOT_PASSWORD=1 mariadb:11 --port=3316 --bind-address=127.0.0.1")
    sh("docker run -d --name aya-wpp --network host -e WORDPRESS_DB_HOST=127.0.0.1:3316 -e WORDPRESS_DB_USER=wp "
       "-e WORDPRESS_DB_PASSWORD=wp -e WORDPRESS_DB_NAME=wp "
       f"-v {PLUGIN}:/var/www/html/wp-content/plugins/authyouragent:ro "
       "wordpress:php8.3-apache bash -c \"sed -i 's/Listen 80$/Listen 8091/' /etc/apache2/ports.conf && "
       "sed -i 's/:80>/:8091>/' /etc/apache2/sites-enabled/000-default.conf && docker-entrypoint.sh apache2-foreground\"")
    for _ in range(60):
        try:
            if httpx.get(WP + "/wp-admin/install.php", timeout=5).status_code in (200, 302):
                break
        except Exception:
            pass
        time.sleep(2)
    wp(f"core install --url={WP} --title='Lamp Shop' --admin_user=admin --admin_password=admin-pass-1234 "
       "--admin_email=admin@example.com --skip-email")
    wp("plugin install woocommerce --activate")
    wp("option update woocommerce_currency USD")
    wp("option update woocommerce_coming_soon no")
    wp("option update woocommerce_enable_guest_checkout no")
    wp("rewrite structure '/%postname%/' --hard")
    wp("wc tool run install_pages --user=admin")
    wp("option update woocommerce_cod_settings '{\"enabled\":\"yes\",\"title\":\"Cash on delivery\"}' --format=json")
    for name, price in (("Brass lighthouse lamp", "45.00"), ("Lamp wick", "3.50")):
        wp(f"wc product create --name='{name}' --regular_price={price} --user=admin")
wp("plugin activate authyouragent")
wp("option update aya_settings '" + json.dumps({"issuer": S["cloud"], "client_id": CL["client_id"],
   "client_secret": CL["client_secret"], "confirm_orders": "1"}) + "' --format=json")
# the dev cloud uses a tailnet certificate the container trusts via the host CA store
PIDS = {n: int(wp(f"post list --post_type=product --name={n} --field=ID"))
        for n in ("brass-lighthouse-lamp", "lamp-wick")}
print("WordPress ready, products", PIDS, flush=True)

# ------------------------------------------------------------------ owner's phone
sys.path.insert(0, ROOT)
from test_softauth import SoftAuthenticator
PASSKEY = SoftAuthenticator(origin=S["cloud"])
d = th.get("/api/webauthn/register/options").json()
th.post("/api/webauthn/register/verify", json={"challenge": d["challenge"],
        "attestation": PASSKEY.register(d["options"])}).raise_for_status()
handled, cards = set(), []
mode = {"oidc": "approve"}   # what the "phone" does with the next card
stop = threading.Event()
def phone():
    while not stop.is_set():
        for t in th.get("/api/me").json().get("pending", []):
            if t["kind"] == "oidc" and t["id"] not in handled:
                handled.add(t["id"]); cards.append({**t, "binding_message": (t.get("oidc") or {}).get("binding_message", "")})
                if mode["oidc"] != "approve":
                    th.post(f"/api/txn/{t['id']}/response", json={"approve": False})
                    continue
                o = th.get(f"/api/txn/{t['id']}/assertion-options").json()
                rr = th.post(f"/api/txn/{t['id']}/response", json={"approve": True, "assertion": PASSKEY.get_assertion(o["options"])})
                if rr.status_code >= 400:
                    print("  phone approval refused:", rr.status_code, rr.text[:200], flush=True)
        time.sleep(0.4)
threading.Thread(target=phone, daemon=True).start()

sys.path.insert(0, os.path.join(ROOT, "sdk"))
from authyouragent.agent import AgentClient
agent = AgentClient(base_url=S["cloud"], agent_id=S["agent_id"], privkey_pem=S["agent_key"].encode(), poll_interval=0.4)

def sign_in():
    s = httpx.Client(timeout=60, follow_redirects=False)
    page = s.get(WP + "/my-account/").text
    m = re.search(r'id="authyouragent-signin" href="([^"]+)"', page)
    if not m:
        return s, None, page
    r = s.get(html.unescape(m.group(1)))
    cb = agent.oidc_signin(r.headers["location"], timeout=120)
    r = s.get(cb)
    return s, r, page

# ------------------------------------------------------------------ sign-in
s, r, page = sign_in()
check("button on the WooCommerce sign-in form", r is not None, page[:200])
check("callback signs in and redirects", r.status_code == 302, r.status_code)
acct = s.get(WP + "/my-account/").text
check("agent is signed in to My account", "woocommerce-MyAccount-navigation" in acct, acct[:200])
users = json.loads(wp("user list --format=json --fields=ID,user_login,display_name,roles"))
agents = [u for u in users if "agent of" in u["display_name"]]
check("one agent account, named for what it is", len(agents) == 1 and agents[0]["display_name"].startswith("Jarvis (agent of"), users)
check("agent role is customer", agents and agents[0]["roles"] == "customer", agents)
uid = agents[0]["ID"]
s2, r2, _ = sign_in()
users2 = json.loads(wp("user list --format=json --fields=ID,display_name"))
check("second sign-in reuses the same account", len([u for u in users2 if "agent of" in u["display_name"]]) == 1, users2)
check("no admin bar for agents", "wpadminbar" not in s.get(WP + "/").text)
state_cookie_forgery = httpx.get(WP + "/wp-login.php?action=authyouragent_callback&state=x&code=y", timeout=30)
check("callback without the browser's state is refused", state_cookie_forgery.status_code == 403, state_cookie_forgery.status_code)

# ------------------------------------------------------------------ checkout (Store API, what block checkout and agents use)
def store(sess):
    n = sess.get(WP + "/wp-json/wc/store/v1/cart").headers.get("Nonce")
    return {"Nonce": n, "Content-Type": "application/json"}

def add(sess, pid, q=1):
    return sess.post(WP + "/wp-json/wc/store/v1/cart/add-item", headers=store(sess), json={"id": pid, "quantity": q})

ADDR = {"first_name": "James", "last_name": "K", "address_1": "1 Main", "city": "Gaborone", "postcode": "0000",
        "country": "BW", "email": "agent-orders@example.com", "phone": "123"}
def checkout(sess):
    return sess.post(WP + "/wp-json/wc/store/v1/checkout", headers=store(sess),
                     json={"billing_address": ADDR, "shipping_address": {k: v for k, v in ADDR.items() if k not in ("email",)},
                           "payment_method": "cod"})

add(s, PIDS["brass-lighthouse-lamp"])
n0 = len(cards)
r = checkout(s)
check("first Place order waits for the customer (409)", r.status_code == 409 and "confirm on their phone" in r.text, r.text)
t0 = time.time()
while len(cards) == n0 and time.time() - t0 < 20:
    time.sleep(0.3)
card = cards[-1] if len(cards) > n0 else {}
msg = card.get("binding_message", "")
check("phone shows the shop's words", msg.startswith("Pay $45.00 at Lamp Shop for Brass lighthouse lamp"), card)
for _ in range(10):
    r = checkout(s)
    if r.status_code != 409 or "Still waiting" not in r.text:
        break
    time.sleep(1)
check("after approval the order is placed", r.status_code == 200 and r.json().get("status") in ("processing", "on-hold", "pending"), r.text[:300])
oid = r.json().get("order_id") if r.status_code == 200 else None
if oid:
    notes = wp(f"wc order_note list {oid} --user=admin --fields=note --format=json")
    check("order note records the agent and the confirmation", "customer confirmed on their phone" in notes and msg[:40] in notes, notes)
    meta = wp(f"post meta get {oid} _aya_confirmed")
    check("order keeps the confirmed text", meta == msg, meta)

# a used confirmation does not carry over; a changed basket asks again
add(s, PIDS["brass-lighthouse-lamp"]); add(s, PIDS["lamp-wick"], 2)
n1 = len(cards)
mode["oidc"] = "deny"
r = checkout(s)
check("new basket asks again", r.status_code == 409, r.text)
t0 = time.time()
while len(cards) == n1 and time.time() - t0 < 20:
    time.sleep(0.3)
check("multi-item message", len(cards) > n1 and cards[-1]["binding_message"].startswith("Pay $52.00 at Lamp Shop for 3 items: Brass lighthouse lamp, Lamp wick (x2)"),
      cards[-1].get("binding_message") if len(cards) > n1 else "no card")
time.sleep(1.5)
for _ in range(10):
    r = checkout(s)
    if "Still waiting" not in r.text:
        break
    time.sleep(1)
check("declined: no order", r.status_code == 409 and "declined" in r.text, r.text)
orders = json.loads(wp("wc shop_order list --user=admin --format=json --fields=id"))
check("only the approved order exists", len(orders) == 1, orders)

# approve once, then change the basket before placing: must ask again
mode["oidc"] = "approve"
n2 = len(cards)
r = checkout(s)
t0 = time.time()
while len(cards) == n2 and time.time() - t0 < 20:
    time.sleep(0.3)
time.sleep(1.5)
add(s, PIDS["lamp-wick"])  # basket changes after approval
n3 = len(cards)
r = checkout(s)
check("approval does not cover a changed basket", r.status_code == 409 and "Waiting for the customer" in r.text, r.text)

# a person's ordinary account is not gated
wp("user create shopper shopper@example.com --role=customer --user_pass=shopper-pass-1234")
p = httpx.Client(timeout=60, follow_redirects=True)
p.post(WP + "/wp-login.php", data={"log": "shopper", "pwd": "shopper-pass-1234", "wp-submit": "Log In", "testcookie": "1"},
       cookies={"wordpress_test_cookie": "WP Cookie check"})
add(p, PIDS["lamp-wick"])
r = checkout(p)
check("ordinary customers check out as before", r.status_code == 200, r.text[:200])
shopper_oid = r.json().get("order_id") if r.status_code == 200 else None

# ------------------------------------------------------------------ Web Bot Auth (3.3) + order badges (3.4)
# A throwaway agent on authyouragent.com publishes a Web Bot Auth key at its own
# public address; WordPress fetches that key list over the internet.
from authyouragent import webbotauth as W
import base64 as _b64, tempfile
from cryptography.hazmat.primitives import serialization as _ser
WK = W.new_key()
KEYF = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, dir=os.environ.get("TMPDIR")).name
os.chmod(KEYF, 0o600)
json.dump({"pub": W.public_jwk(WK), "d": _b64.urlsafe_b64encode(WK.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw,
           _ser.NoEncryption())).rstrip(b"=").decode()}, open(KEYF, "w"))
LIVE = os.path.join(ROOT, "tests-private", "wba", "live_agent_js.py")
PYX = os.path.join(ROOT, ".venv", "bin", "python")
try:
    up = json.loads(sh(f"{PYX} {LIVE} up {KEYF}"))
    check("WBA: throwaway agent published on authyouragent.com", up["ok"], up)
    AGENT = up["signature_agent"]
    IDENT = AGENT + W.WELL_KNOWN

    def signed_get(path, key=WK, agent=AGENT, tamper=False):
        u = WP + path
        h = W.sign_request(key, "GET", u, agent)
        if tamper:
            h["Signature"] = h["Signature"][:12] + ("A" if h["Signature"][12] != "A" else "B") + h["Signature"][13:]
        return httpx.get(u, headers=h, timeout=60)

    r = signed_get("/shop/")
    check("WBA: signed request from a verified agent is served (200)", r.status_code == 200, r.status_code)
    seen = json.loads(wp("option get aya_wba_seen --format=json"))
    check("WBA: the agent's address is recorded", IDENT in seen and seen[IDENT]["outcome"] == "verified"
          and seen[IDENT]["path"] == "/shop/" and seen[IDENT]["proof"] is True, seen)
    check("WBA: unsigned visitors are not recorded or touched", httpx.get(WP + "/shop/", timeout=30).status_code == 200
          and len(json.loads(wp("option get aya_wba_seen --format=json"))) == len(seen))
    r = signed_get("/shop/", tamper=True)
    check("WBA: invalid signature is served by default (only labelled)", r.status_code == 200, r.status_code)
    seen = json.loads(wp("option get aya_wba_seen --format=json"))
    check("WBA: invalid signature counted apart from the agent", "_invalid" in seen and "does not verify" in seen["_invalid"]["reason"], seen.keys())
    r = signed_get("/shop/", agent="https://chatgpt.com")
    check("WBA: our key claiming chatgpt.com is unverified, served, not attributed", r.status_code == 200
          and "_unverified" in json.loads(wp("option get aya_wba_seen --format=json")), r.status_code)

    # admin: settings page lists the agent; Block / Allow / Reset buttons
    adm = httpx.Client(timeout=60, follow_redirects=True)
    adm.post(WP + "/wp-login.php", data={"log": "admin", "pwd": "admin-pass-1234", "wp-submit": "Log In", "testcookie": "1"},
             cookies={"wordpress_test_cookie": "WP Cookie check"})
    def settings():
        return adm.get(WP + "/wp-admin/options-general.php?page=authyouragent").text
    pg = settings()
    check("WBA: settings page lists the agent with its labels", html.escape(AGENT) in pg and "Auth Your Agent: its owner approves" in pg
          and "key list signed for its own address" in pg, pg[pg.find("Signed agents"):][:600])

    def press(rule):
        pg = settings()
        for f in re.findall(r'<form method="post" action="[^"]*admin-post\.php"[^>]*>(.*?)</form>', pg, re.S):
            if f'value="{html.escape(IDENT)}"' in f and f'name="rule" value="{rule}"' in f:
                fields = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', f))
                return adm.post(WP + "/wp-admin/admin-post.php", data={k: html.unescape(v) for k, v in fields.items()})
        return None
    r = press("block")
    check("WBA: Block button saves a rule", r is not None and json.loads(wp("option get aya_wba_rules --format=json")).get(IDENT) == "block",
          r.status_code if r else "no button")
    r = signed_get("/shop/")
    check("WBA: blocked agent gets 403", r.status_code == 403 and "does not accept requests from this agent" in r.text, r.status_code)
    check("WBA: unsigned visitors still get 200 while the agent is blocked", httpx.get(WP + "/shop/", timeout=30).status_code == 200)
    forged = adm.post(WP + "/wp-admin/admin-post.php", data={"action": "aya_wba_rule", "agent": IDENT, "rule": "allow", "_wpnonce": "x"})
    check("WBA: a rule change without the admin nonce is refused", forged.status_code in (403, 400) or "link you followed has expired" in forged.text,
          forged.status_code)
    press("clear")
    check("WBA: Reset removes the rule", signed_get("/shop/").status_code == 200)
    o = json.loads(wp("option get aya_settings --format=json")); o["wba_mode"] = "listed"
    wp("option update aya_settings '" + json.dumps(o) + "' --format=json")
    r = signed_get("/shop/")
    check("WBA: allow-list mode refuses an agent not yet allowed", r.status_code == 403 and "only agents it has allowed" in r.text, r.status_code)
    press("allow")
    check("WBA: allow-list mode serves an allowed agent", signed_get("/shop/").status_code == 200)
    check("WBA: allow-list mode leaves unsigned visitors alone", httpx.get(WP + "/shop/", timeout=30).status_code == 200)
    o["wba_mode"] = "all"; o["wba_refuse_invalid"] = "1"
    wp("option update aya_settings '" + json.dumps(o) + "' --format=json")
    r = signed_get("/shop/", tamper=True)
    check("WBA: 'refuse invalid' turns a forged signature into 403", r.status_code == 403 and "invalid agent signature" in r.text, r.status_code)
    o["wba_refuse_invalid"] = "0"
    wp("option update aya_settings '" + json.dumps(o) + "' --format=json")

    # a signed agent places an order (Store API), with the owner's phone approval
    def signed_checkout(sess):
        u = WP + "/wp-json/wc/store/v1/checkout"
        return sess.post(u, headers={**store(sess), **W.sign_request(WK, "POST", u, AGENT)},
                         json={"billing_address": ADDR, "shipping_address": {k: v for k, v in ADDR.items() if k != "email"},
                               "payment_method": "cod"})
    mode["oidc"] = "approve"
    r = signed_checkout(s)
    for _ in range(25):   # first call asks the phone (or finds a pending approval); retry while waiting
        if r.status_code != 409 or "confirm" not in r.text:
            break
        time.sleep(1)
        r = signed_checkout(s)
    soid = r.json().get("order_id") if r.status_code == 200 else None
    check("WBA: signed agent's order placed after the phone approval", soid is not None, r.text[:300])
    if soid:
        meta = wp(f"post meta get {soid} _aya_wba_agent")
        check("WBA: order records the signing agent's address", meta == IDENT, meta)
        notes = wp(f"wc order_note list {soid} --user=admin --field=note")
        check("WBA: order note says it was placed by a signed agent", f"Placed by a signed agent: {AGENT} (" in notes,
              [n for n in notes.splitlines() if "Placed by" in n])

    # 3.4 badges: orders list and order page
    def order_screen(oid_):
        r_ = adm.get(WP + f"/wp-admin/admin.php?page=wc-orders&action=edit&id={oid_}")
        if r_.status_code != 200 or "aya-badges" not in r_.text and "post-body" not in r_.text:
            r_ = adm.get(WP + f"/wp-admin/post.php?post={oid_}&action=edit")
        return r_.text
    lst = adm.get(WP + "/wp-admin/admin.php?page=wc-orders").text
    if "wc-orders" not in lst or "aya-badge" not in lst:
        lst = adm.get(WP + "/wp-admin/edit.php?post_type=shop_order").text
    rows = {m.group(1): m.group(2) for m in re.finditer(r'<tr id="(?:order|post)-(\d+)"(.*?)</tr>', lst, re.S)}
    check("3.4: orders list has an Agent column", ">Agent<" in lst, lst[:200])
    check("3.4: approved agent order shows 'Owner approved on phone' in the list", oid and "Owner approved on phone" in rows.get(str(oid), ""),
          rows.get(str(oid), "row missing")[:300])
    check("3.4: an ordinary customer's order has no badge", shopper_oid and 'class="aya-badge' not in rows.get(str(shopper_oid), 'class="aya-badge'),
          rows.get(str(shopper_oid), "row missing")[:300])
    if soid:
        check("3.4: signed agent's approved order shows both badges in the list",
              "Owner approved on phone" in rows.get(str(soid), "") and "Signed agent" in rows.get(str(soid), ""), rows.get(str(soid), "row missing")[:300])
    pg = order_screen(oid)
    check("3.4: order page shows the badge and the approved text", "Owner approved on phone" in pg and html.escape(msg[:30]) in pg,
          pg[pg.find("aya-badges"):][:400])
    pg = order_screen(shopper_oid)
    check("3.4: ordinary order page has no badge", 'class="aya-badge' not in pg and "aya-badges" not in pg)
    # an agent order placed with confirmation switched off: labelled, but NOT as approved
    o["confirm_orders"] = "0"
    wp("option update aya_settings '" + json.dumps(o) + "' --format=json")
    add(s, PIDS["lamp-wick"])
    r = checkout(s)
    uoid = r.json().get("order_id") if r.status_code == 200 else None
    o["confirm_orders"] = "1"
    wp("option update aya_settings '" + json.dumps(o) + "' --format=json")
    pg = order_screen(uoid) if uoid else ""
    check("3.4: agent order without a phone confirmation is not badged as approved",
          uoid and "Owner approved on phone" not in pg and "Agent order, not confirmed" in pg, (r.status_code, r.text[:200]))
finally:
    sh(f"{PYX} {LIVE} revoke {KEYF}", False)
    sh(f"{PYX} {LIVE} delete {KEYF}", False)
    os.unlink(KEYF)

# ------------------------------------------------------------------ sign-out
bad = httpx.post(WP + "/wp-json/authyouragent/v1/backchannel-logout", data={"logout_token": "a.b.c"}, timeout=30)
check("forged logout token refused", bad.status_code == 400, bad.text)
still = "woocommerce-MyAccount-navigation" in s.get(WP + "/my-account/").text
check("agent still signed in before revoke", still)
g = [x for x in th.get("/api/me").json()["grants"] if x["site"] == "localhost"]
t0 = time.time()
for x in g:
    th.post(f"/api/grants/{x['id']}/revoke")
out = None
while time.time() - t0 < 30:
    if "woocommerce-MyAccount-navigation" not in s.get(WP + "/my-account/").text:
        out = time.time() - t0; break
    time.sleep(1)
check("revoke signs the agent out of WordPress (back-channel)", out is not None and out < 15, out)
check("the other browser session ended too", "woocommerce-MyAccount-navigation" not in s2.get(WP + "/my-account/").text)

stop.set()
if "--keep" not in sys.argv:
    sh("docker rm -f aya-wpp aya-wpp-db >/dev/null 2>&1; true", False)
print(f"\n{'ALL PASS' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
