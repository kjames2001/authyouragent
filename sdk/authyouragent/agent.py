"""authyouragent.agent — agent-side SDK for the Auth Your Agent cloud (vertical slice).

An agent that wants to act on a user's behalf on a site:

  s = AgentClient(base_url="https://authyouragent.com",
                  agent_id="ag_xxx", privkey_pem="-----BEGIN PRIVATE KEY-----...")
  s.ensure_grant("jobboard.example", scopes=["list", "apply"])
  # → pushes a biometric approval to the user's phone; blocks until answered
  s.call("jobboard.example", "GET", "https://jobs.example.com/list",
         token=..., dpop=...)

In practice the agent embeds this around its HTTP calls:

  req = s.request("GET", "https://jobs.example.com/jobs")
  # sends Authorization: Bearer <AT> + DPoP header; auto-refreshes tokens;
  # auto-requests step-up when the site returns 403 stepup_required

Key material: the agent holds its Ed25519/EC P-256 private key; the cloud
never sees it. The DPoP key IS the agent key (single key, per RFC 9449).
"""

import os
import sys
import json
import threading
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


class AgentError(Exception):
    pass


class AgentClient:
    def __init__(self, base_url, agent_id, privkey_pem, poll_interval=1.5,
                 timeout=60, verify=True):
        self.base = base_url.rstrip("/")
        self.agent_id = agent_id
        self.key = serialization.load_pem_private_key(
            privkey_pem.encode() if isinstance(privkey_pem, str) else privkey_pem,
            password=None)
        self.pub = self.key.public_key()
        self.poll_interval = poll_interval
        self.verify = verify
        self.client = httpx.Client(timeout=timeout, verify=verify)
        # per-site token cache: an access token is audience-bound (aud=site),
        # so a token minted for site A must never be sent to site B.
        self._access_by_site = {}   # site -> (token, exp_float)
        self._refresh_by_site = {}  # site -> refresh token
        self._last_site = None
        self._lock = threading.RLock()
        self._jwk = {
            "kty": "EC", "crv": "P-256",
            "x": b64(self.pub.public_numbers().x.to_bytes(32, "big")),
            "y": b64(self.pub.public_numbers().y.to_bytes(32, "big")),
        }

    # ------------------------------------------------ legacy cache accessors
    # Back-compat for callers/tests that poke `_access` / `_refresh` directly:
    # reading returns the most-recently-used site's entry; assigning None
    # clears the cache for ALL sites.

    @property
    def _access(self):
        return self._access_by_site.get(self._last_site)

    @_access.setter
    def _access(self, v):
        with self._lock:
            if v is None:
                self._access_by_site.clear()
            elif self._last_site is not None:
                self._access_by_site[self._last_site] = v

    @property
    def _refresh(self):
        return self._refresh_by_site.get(self._last_site)

    @_refresh.setter
    def _refresh(self, v):
        with self._lock:
            if v is None:
                self._refresh_by_site.clear()
            elif self._last_site is not None:
                self._refresh_by_site[self._last_site] = v

    def _poll_headers(self):
        # the cloud only reveals a txn's stepup_token to its own agent: every
        # poll carries a FRESH short-lived agent JWT (they expire)
        return {"X-Agent-JWT": self._agent_jwt()}

    # ------------------------------------------------------------ crypto

    def _agent_jwt(self, ttl=300):
        """Signed statement of agency, verified by the cloud against our pubkey."""
        now = int(time.time())
        return pyjwt.encode(
            {"iss": self.agent_id, "sub": self.agent_id,
             "iat": now, "exp": now + ttl, "type": "agent"},
            self.key, algorithm="ES256")

    def oidc_header(self, authorize_url, ttl=60):
        """X-AuthYourAgent-Agent value for one /oidc/authorize request: an
        agent JWT bound to that exact URL (htu) with a one-time jti."""
        import secrets
        now = int(time.time())
        return pyjwt.encode(
            {"iss": self.agent_id, "sub": self.agent_id, "iat": now, "exp": now + ttl,
             "type": "agent", "htu": authorize_url, "jti": secrets.token_urlsafe(16)},
            self.key, algorithm="ES256")

    def oidc_signin(self, authorize_url, timeout=330, client=None):
        """Complete a "Sign in with Auth Your Agent" (OpenID Connect) sign-in
        without a browser. `authorize_url` is the link the site's login
        button points to. Waits for the owner's phone approval when one is
        needed, and returns the site's redirect URL carrying ?code=...
        (the caller then GETs it with its own HTTP session, so the site's
        session cookie lands where the agent works). Raises PermissionError
        when the owner denies, the approval times out, or access is revoked."""
        from urllib.parse import urljoin, urlsplit, parse_qs
        own = client is None
        c = client or httpx.Client(timeout=30, verify=self.verify)
        try:
            r = c.get(authorize_url, headers={"X-AuthYourAgent-Agent": self.oidc_header(authorize_url)},
                      follow_redirects=False)
            if r.status_code != 302:
                raise PermissionError(f"sign-in refused ({r.status_code}): {r.text[:200]}")
            loc = urljoin(authorize_url, r.headers["location"])
            cloud = urlsplit(authorize_url)
            if urlsplit(loc).netloc == cloud.netloc and urlsplit(loc).path.startswith("/oidc/authorize/wait/"):
                status_url = loc.split("?", 1)[0] + "/status?" + loc.split("?", 1)[1]
                deadline = time.time() + timeout
                while True:
                    d = c.get(status_url).json()
                    if d.get("redirect"):
                        loc = d["redirect"]
                        break
                    if d.get("status") != "pending" or time.time() > deadline:
                        raise PermissionError(f"sign-in not approved ({d.get('status', 'timeout')})")
                    time.sleep(self.poll_interval)
            q = parse_qs(urlsplit(loc).query)
            if "error" in q:
                raise PermissionError(f"sign-in refused: {q['error'][0]} "
                                      f"{q.get('error_description', [''])[0]}".strip())
            return loc
        finally:
            if own:
                c.close()

    def _dpop_proof(self, method, url, access_token=None):
        ath = None
        if access_token:
            import hashlib, base64
            ath = base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
        payload = {"htm": method.upper(),
                   # 'url' for the current cloud, 'htu' (RFC 9449 name)
                   # for clouds that accept the standard claim
                   "url": url, "htu": url, "iat": int(time.time()),
                   "jti": "j_" + _rand()[:12]}
        if ath:
            payload["ath"] = ath
        # RFC 9449: the key (jwk) lives in the DPoP proof's JOSE header.
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._jwk}
        h = b64(json.dumps(header, separators=(",", ":")).encode())
        p = b64(json.dumps(payload, separators=(",", ":")).encode())
        signing = (h + "." + p).encode()
        der = self.key.sign(signing, ec.ECDSA(hashes.SHA256()))
        # JWS ES256 signatures are raw r||s, 64 bytes (RFC 7518 §3.4), not DER
        r, s_ = decode_dss_signature(der)
        return h + "." + p + "." + b64(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))

    # ------------------------------------------------------------ grants

    def ensure_grant(self, site, scopes, wait=True):
        """Ask the cloud for access to `site`. Pushes approval to the user's
        phone; if `wait`, blocks until the user approves/denies (max ~5 min).
        Returns True if the grant is usable."""
        try:
            r = self.client.post(f"{self.base}/api/v1/authz-requests", json={
                "agent_id": self.agent_id, "site": site,
                "scopes": scopes, "agent_jwt": self._agent_jwt()})
        except httpx.HTTPError as e:
            raise AgentError(f"cloud unreachable: {e}")
        if r.status_code == 403:
            # The only 403 this endpoint emits is check_agent's
            # "agent revoked by owner" (409 means "grant already active").
            # Surface revocation loudly; anything else -> try the token path.
            detail = ""
            try:
                b = r.json()
                detail = (b.get("detail") if isinstance(b.get("detail"), str)
                          else b.get("error", "")) or ""
            except Exception:
                pass
            if "revoked" in detail.lower():
                raise AgentError(f"agent revoked by owner: {detail}")
            return self._try_token(site)
        if r.status_code == 409:
            return True
        if r.status_code >= 400:
            raise AgentError(f"authz request failed: {r.status_code} {r.text[:200]}")
        txn = _txn_id(r)
        print(f"[authyouragent] approval requested ({txn}) — waiting for phone…")
        if not wait:
            return None
        deadline = time.time() + 330
        while time.time() < deadline:
            try:
                p = self.client.get(f"{self.base}/api/v1/authz-requests/{txn}",
                                    headers=self._poll_headers())
            except httpx.HTTPError:
                time.sleep(self.poll_interval)
                continue
            if p.status_code >= 500:
                # transient server error — keep polling (the phone may still
                # respond), do not kill the whole flow over one bad poll
                time.sleep(self.poll_interval)
                continue
            if p.status_code == 404:
                raise AgentError("approval txn vanished from the cloud")
            try:
                b = p.json()
                st = b.get("status", "pending") if isinstance(b, dict) else "pending"
            except Exception:
                st = "pending"
            if st == "approved":
                print("[authyouragent] approved ✓")
                return self._try_token(site)
            if st in ("denied", "expired"):
                print(f"[authyouragent] {st}")
                raise AgentError(f"approval {st} by user")
            time.sleep(self.poll_interval)
        raise AgentError("approval timed out")

    def _try_token(self, site):
        try:
            self._get_access(site)
            return True
        except AgentError:
            return False

    # ------------------------------------------------------------ tokens

    def _get_access(self, site, rotate=True):
        with self._lock:
            return self._get_access_locked(site, rotate)

    def _get_access_locked(self, site, rotate=True):
        # cache entry: self._access_by_site[site] = (access_token, exp_float)
        self._last_site = site
        cur = self._access_by_site.get(site)
        if cur and float(cur[1]) > time.time() + 30:
            return cur[0]
        refresh = self._refresh_by_site.get(site)
        try:
            if refresh:
                body = {"agent_id": self.agent_id, "site": site,
                        "agent_jwt": self._agent_jwt(),
                        "refresh_token": refresh}
                r = self.client.post(f"{self.base}/api/v1/token", json=body)
                # the cloud ROTATES the refresh token on every issuance; a
                # stale/rotated-away token is a 401 — drop it and retry once
                # via the initial-approval path (which re-mints the grant's
                # refresh). A misbehaving agent must not crash on rotation.
                if r.status_code == 401:
                    self._refresh_by_site.pop(site, None)
                    body = {"agent_id": self.agent_id, "site": site,
                            "agent_jwt": self._agent_jwt()}
                    r = self.client.post(f"{self.base}/api/v1/token", json=body)
            else:
                body = {"agent_id": self.agent_id, "site": site,
                        "agent_jwt": self._agent_jwt()}
                r = self.client.post(f"{self.base}/api/v1/token", json=body)
        except httpx.HTTPError as e:
            raise AgentError(f"cloud unreachable: {e}")
        if r.status_code == 403:
            raise AgentError("no grant — call ensure_grant() first")
        if r.status_code >= 400:
            raise AgentError(f"token fetch failed: {r.status_code} {r.text[:200]}")
        try:
            d = r.json()
            at = d["access_token"]
        except Exception:
            raise AgentError(f"token response malformed: {r.text[:200]}")
        exp = None
        # the token endpoint returns expires_in (seconds); prefer it
        try:
            if d.get("expires_in") is not None:
                exp = time.time() + float(d["expires_in"])
        except (TypeError, ValueError):
            exp = None
        if exp is None:
            try:
                claims = pyjwt.decode(at, options={"verify_signature": False})
                exp = float(claims.get("exp"))
            except Exception:
                exp = time.time()
        self._access_by_site[site] = (at, exp)
        if d.get("refresh_token"):
            self._refresh_by_site[site] = d["refresh_token"]
        else:
            self._refresh_by_site.pop(site, None)
        return at

    # ------------------------------------------------------------ calls

    def request(self, method, url, stepup_action=None, site=None, **kwargs):
        """Perform an HTTP request through Auth Your Agent: attaches Bearer + DPoP,
        auto-refreshes tokens, and on a 403 'stepup_required' from the site,
        requests a one-time step-up grant (phone prompt) and retries ONCE.
        Each attempt mints a FRESH DPoP proof (and a fresh access token if
        the old one is within 30s of expiry) — reusing a proof from the
        first attempt 401s after ~2 min (DPoP iat window) or once the
        access token has rolled.

        `site` is the site id you were granted; it defaults to the URL's
        host. Pass it when the site is reached at another address (a
        local test server, a regional API host)."""
        site = site or url.split("/")[2].split(":")[0]
        at = self._get_access(site)
        headers = dict(kwargs.pop("headers", {}))
        resp = self._do_request(method, url, at, headers, kwargs)
        if resp.status_code == 403 and stepup_action:
            try:
                body = resp.json()
            except Exception:
                return resp
            # tolerate both the flat {"error": ...} and FastAPI's nested
            # {"detail": {"error": ...}} shapes
            if not isinstance(body, dict):
                return resp          # not a step-up signal; surface as-is
            err_obj = body.get("detail") if isinstance(body.get("detail"), dict) else body
            if err_obj.get("error") == "stepup_required":
                # a site that describes the action itself sends a signed
                # stepup_request: pass it through unchanged (the owner sees
                # the site's words, and the cloud checks the signature)
                sr = err_obj.get("stepup_request")
                st = self._stepup(site, stepup_action, sr if isinstance(sr, str) else None)
                if st:
                    # retry: fresh token (the old one may have expired
                    # during the phone wait) + fresh DPoP proof bound to it
                    headers["X-AuthYourAgent-Stepup"] = st
                    at2 = self._get_access(site, rotate=False)
                    return self._do_request(method, url, at2, headers, kwargs)
        return resp

    def _do_request(self, method, url, at, headers, kwargs):
        # DPoP: one fresh proof PER request (htm/url/iat/ath all bind to
        # this exact call — RFC 9449).
        h = dict(headers)
        h["Authorization"] = f"Bearer {at}"
        h["DPoP"] = self._dpop_proof(method, url, at)
        try:
            return self.client.request(method, url, headers=h, **kwargs)
        except httpx.HTTPError as e:
            raise AgentError(f"request failed: {e}")

    def check_status(self):
        """Check whether this agent is still authorized by the owner.
        Returns a dict with 'status' (active/revoked), 'global_flag',
        'agent_name', and 'revoked_sites'.
        Raises AgentError if the server cannot be reached or the JWT is invalid."""
        try:
            r = self.client.get(
                f"{self.base}/api/v1/agent-status",
                headers={"X-Agent-JWT": self._agent_jwt()},
                params={"agent_id": self.agent_id},
                timeout=10)
        except httpx.HTTPError as e:
            raise AgentError(f"status check failed: {e}")
        if r.status_code == 401:
            raise AgentError("agent JWT rejected — the key may be invalid or the agent deleted")
        if r.status_code == 403:
            return {"status": "revoked", "global_flag": "revoked", "revoked_sites": []}
        if r.status_code != 200:
            raise AgentError(f"status check returned {r.status_code}: {r.text[:200]}")
        return r.json()

    def report_status(self, status, site="", detail=""):
        """Report this agent's current status to the server so the owner's
        dashboard shows what the agent is doing. Best-effort: errors are
        printed but not raised, so a reporting failure never blocks the agent."""
        try:
            r = self.client.post(
                f"{self.base}/api/v1/agent-status",
                json={"agent_id": self.agent_id, "agent_jwt": self._agent_jwt(),
                      "status": status, "site": site, "detail": detail},
                timeout=10)
            if r.status_code >= 400:
                print(f"[authyouragent] status report failed: {r.status_code}")
        except Exception as e:
            print(f"[authyouragent] status report failed: {e}")

    def request_approval(self, site, action, wait=290, on_pending=None):
        """Ask the owner's phone to approve one action, and wait for the answer.

        For actions outside a website that has adopted Auth Your Agent: a
        publish, a deploy, a payment the agent makes some other way. Returns
        "approved", "denied", "expired" or "cancelled". Raises AgentError if
        the request cannot be made (bad key, agent revoked, server down).
        on_pending(txn_id) is called once the request is on the phone."""
        try:
            r = self.client.post(f"{self.base}/api/v1/agent-approval", json={
                "agent_id": self.agent_id, "site": site, "action": action,
                "agent_jwt": self._agent_jwt()}, timeout=15)
        except httpx.HTTPError as e:
            raise AgentError(f"approval request failed: {e}")
        if r.status_code != 200:
            raise AgentError(f"approval request returned {r.status_code}: {r.text[:200]}")
        txn = _txn_id(r)
        if on_pending:
            on_pending(txn)
        deadline = time.time() + max(1, min(int(wait), 290))
        while time.time() < deadline:
            time.sleep(self.poll_interval)
            try:
                p = self.client.get(f"{self.base}/api/v1/authz-requests/{txn}",
                                    headers=self._poll_headers(), timeout=10)
                st = p.json().get("status") if p.status_code == 200 else None
            except Exception:
                continue
            if st in ("approved", "denied", "expired", "cancelled"):
                return st
        return "expired"

    def notify(self, text, title=""):
        """Send the owner a one-way note on their phone ("done", "stuck").
        Nothing to approve. Returns True if at least one device got it.
        Raises AgentError if the note cannot be sent."""
        try:
            r = self.client.post(f"{self.base}/api/v1/agent-notify", json={
                "agent_id": self.agent_id, "agent_jwt": self._agent_jwt(),
                "text": text, "title": title}, timeout=15)
        except httpx.HTTPError as e:
            raise AgentError(f"note failed: {e}")
        if r.status_code != 200:
            raise AgentError(f"note returned {r.status_code}: {r.text[:200]}")
        return bool(r.json().get("sent"))

    def _stepup(self, site, action, stepup_request=None):
        body = {"agent_id": self.agent_id, "site": site, "action": action,
                "agent_jwt": self._agent_jwt()}
        if stepup_request:
            body["stepup_request"] = stepup_request
        try:
            r = self.client.post(f"{self.base}/api/v1/stepup", json=body)
        except httpx.HTTPError as e:
            print(f"[authyouragent] stepup request failed: {e}")
            return None
        if r.status_code >= 400:
            print(f"[authyouragent] stepup request failed: {r.text}")
            return None
        txn = _txn_id(r)
        print(f"[authyouragent] step-up requested ({txn}) — waiting for phone…")
        deadline = time.time() + 330
        while time.time() < deadline:
            try:
                p = self.client.get(f"{self.base}/api/v1/authz-requests/{txn}",
                                    headers=self._poll_headers())
            except httpx.HTTPError:
                time.sleep(self.poll_interval)
                continue
            if p.status_code >= 500:
                # transient server error — keep polling (the phone may still
                # respond), do not kill the whole flow over one bad poll
                time.sleep(self.poll_interval)
                continue
            if p.status_code == 404:
                return None
            try:
                st = p.json()
            except Exception:
                st = None
            if not isinstance(st, dict):
                time.sleep(self.poll_interval)
                continue
            if st.get("status") == "approved" and st.get("stepup_token"):
                print("[authyouragent] step-up approved ✓")
                return st["stepup_token"]
            if st.get("status") in ("denied", "expired"):
                print(f"[authyouragent] step-up {st.get('status')}")
                return None
            time.sleep(self.poll_interval)
        return None


def _txn_id(r):
    try:
        b = r.json()
    except Exception:
        raise AgentError(f"cloud returned non-JSON: {r.text[:200]}")
    if not isinstance(b, dict) or not b.get("txn_id"):
        raise AgentError(f"cloud response missing txn_id: {r.text[:200]}")
    return b["txn_id"]


def _rand(n=16):
    import secrets
    return secrets.token_hex(n)


def b64(x: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def b64dec(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def keygen():
    """§10.1: generate an agent keypair LOCALLY, in the agent runtime.
    The private key never touches the network. Returns (privkey_pem, pubkey_pem)."""
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def agent_jwk(pubkey_pem: str) -> dict:
    """Emit the RFC 7515 JWK the PWA posts when registering an agent whose
    key was generated locally by the agent runtime."""
    pub = serialization.load_pem_public_key(
        pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem)
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64(n.x.to_bytes(32, "big")),
            "y": b64(n.y.to_bytes(32, "big"))}

# ------------------------------------------------------------ CLI
#   python -m authyouragent keygen --name "Hermes JARVIS"
#   -> prints {"agent_key": {...}} ; the agent keeps the privkey, and the
#      user's phone registers the pubkey with the cloud (cloud never sees
#      the private key — §10.1).

def _cli_keygen(name):
    priv, pub = keygen()
    print(json.dumps({
        "agent_key": {
            "name": name,
            "jwk": agent_jwk(pub),
            "pubkey_pem": pub,
            "privkey_pem": priv,
            "note": ("agent runtime: keep privkey_pem local. "
                     "Phone/PWA: register jwk (+name) with the cloud; "
                     "the cloud will return agent_id, which the runtime "
                     "uses to build its AgentClient."),
        }
    }, indent=2))

def _cli_approve(argv):
    """`authyouragent approve <site> <action>`: ask the owner's phone, exit 0
    only if approved, so a script can gate a step: `... && npm publish`."""
    import argparse
    ap = argparse.ArgumentParser(
        prog="authyouragent approve",
        description="Ask your phone to approve one action. Exits 0 only if you approve it, "
                    "so it can gate a command: authyouragent approve npmjs.com publish && npm publish",
        epilog="exit codes: 0 approved, 1 denied, 2 setup or request error, 3 expired or cancelled. "
               "Agent from --agent-id/--key or AYA_AGENT_ID/AYA_KEY_FILE; server from AYA_CLOUD.")
    ap.add_argument("site", help="where the action happens, e.g. npmjs.com or github.com/you/repo")
    ap.add_argument("action", help="short label shown on your phone, e.g. publish or deploy")
    ap.add_argument("--wait", type=int, default=290, help="seconds to wait for an answer (max 290)")
    ap.add_argument("--agent-id", default=os.environ.get("AYA_AGENT_ID"))
    ap.add_argument("--key", default=os.environ.get("AYA_KEY_FILE"), help="agent private key (PEM)")
    ap.add_argument("--cloud", default=os.environ.get("AYA_CLOUD", "https://authyouragent.com"))
    ap.add_argument("-q", "--quiet", action="store_true", help="print nothing; use the exit code")
    a = ap.parse_args(argv)
    say = (lambda *_: None) if a.quiet else (lambda m: print(m, file=sys.stderr, flush=True))
    if not a.agent_id or not a.key:
        say("authyouragent approve: need --agent-id and --key (or AYA_AGENT_ID / AYA_KEY_FILE)")
        return 2
    try:
        pem = open(os.path.expanduser(a.key)).read()
        agent = AgentClient(base_url=a.cloud, agent_id=a.agent_id, privkey_pem=pem,
                            poll_interval=2, verify=not os.environ.get("AYA_INSECURE"))
        st = agent.request_approval(a.site, a.action, wait=a.wait,
                                    on_pending=lambda t: say(f"waiting for your phone to approve "
                                                             f"'{a.action}' on {a.site} ..."))
    except (OSError, ValueError, AgentError) as e:
        say(f"authyouragent approve: {e}")
        return 2
    say(st)
    return {"approved": 0, "denied": 1}.get(st, 3)


def _cli_notify(argv):
    """`authyouragent notify "<text>"`: a one-way note to the owner's phone,
    for the end of a job: `make deploy; authyouragent notify "deploy: exit $?"`."""
    import argparse
    ap = argparse.ArgumentParser(
        prog="authyouragent notify",
        description="Send a one-way note to your phone, e.g. when a long job ends. Nothing to approve.",
        epilog="exit codes: 0 delivered, 1 sent but no device has notifications on, "
               "2 setup or request error. Text '-' reads standard input. "
               "Agent from --agent-id/--key or AYA_AGENT_ID/AYA_KEY_FILE; server from AYA_CLOUD.")
    ap.add_argument("text", help="the message (up to 600 characters, 12 lines); '-' reads stdin")
    ap.add_argument("--title", default="", help="notification title (default: the agent's name)")
    ap.add_argument("--agent-id", default=os.environ.get("AYA_AGENT_ID"))
    ap.add_argument("--key", default=os.environ.get("AYA_KEY_FILE"), help="agent private key (PEM)")
    ap.add_argument("--cloud", default=os.environ.get("AYA_CLOUD", "https://authyouragent.com"))
    ap.add_argument("-q", "--quiet", action="store_true", help="print nothing; use the exit code")
    a = ap.parse_args(argv)
    say = (lambda *_: None) if a.quiet else (lambda m: print(m, file=sys.stderr, flush=True))
    if not a.agent_id or not a.key:
        say("authyouragent notify: need --agent-id and --key (or AYA_AGENT_ID / AYA_KEY_FILE)")
        return 2
    text = sys.stdin.read() if a.text == "-" else a.text
    try:
        pem = open(os.path.expanduser(a.key)).read()
        agent = AgentClient(base_url=a.cloud, agent_id=a.agent_id, privkey_pem=pem,
                            verify=not os.environ.get("AYA_INSECURE"))
        sent = agent.notify(text, title=a.title)
    except (OSError, ValueError, AgentError) as e:
        say(f"authyouragent notify: {e}")
        return 2
    say("sent" if sent else "recorded, but no device has notifications on")
    return 0 if sent else 1


def _cli_main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["vault"]:
        from .vault_cli import main as vault_main
        return vault_main(argv[1:])
    if argv[:1] == ["approve"]:
        sys.exit(_cli_approve(argv[1:]))
    if argv[:1] == ["notify"]:
        sys.exit(_cli_notify(argv[1:]))
    import argparse
    ap = argparse.ArgumentParser(prog="authyouragent",
                                 epilog="also: authyouragent approve <site> <action>; authyouragent notify <text>; "
                                        "authyouragent vault up|down|status|env")
    ap.add_argument("cmd", choices=["keygen"])
    ap.add_argument("--name", default="agent")
    args = ap.parse_args(argv)
    if args.cmd == "keygen":
        _cli_keygen(args.name)


if __name__ == "__main__":
    _cli_main()
