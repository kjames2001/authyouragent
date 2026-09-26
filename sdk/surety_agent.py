"""surety_agent — agent-side SDK for the Surety cloud (vertical slice).

An agent that wants to act on a user's behalf on a site:

  s = SuretyAgent(base_url="https://hermes.armadillo-lake.ts.net:8443",
                  agent_id="ag_xxx", privkey_pem="-----BEGIN PRIVATE KEY-----...")
  s.ensure_grant("jobboard.example", scopes=["list", "apply"])
  # → pushes a biometric approval to the user's phone; blocks until answered
  s.call("jobboard.example", "GET", "https://hermes.armadillo-lake.ts.net:8443/jobboard/list",
         token=..., dpop=...)

In practice the agent embeds this around its HTTP calls:

  req = s.request("GET", "https://hermes.armadillo-lake.ts.net:8443/jobboard/jobs")
  # sends Authorization: Bearer <AT> + DPoP header; auto-refreshes tokens;
  # auto-requests step-up when the site returns 403 stepup_required

Key material: the agent holds its Ed25519/EC P-256 private key; the cloud
never sees it. The DPoP key IS the agent key (single key, per RFC 9449).
"""

import json
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class SuretyError(Exception):
    pass


class SuretyAgent:
    def __init__(self, base_url, agent_id, privkey_pem, poll_interval=1.5,
                 timeout=60, verify=True):
        self.base = base_url.rstrip("/")
        self.agent_id = agent_id
        self.key = serialization.load_pem_private_key(
            privkey_pem.encode() if isinstance(privkey_pem, str) else privkey_pem,
            password=None)
        self.pub = self.key.public_key()
        self.poll_interval = poll_interval
        self.client = httpx.Client(timeout=timeout, verify=verify)
        self._access = None       # (token, exp)
        self._refresh = None
        self._jwk = {
            "kty": "EC", "crv": "P-256",
            "x": b64(self.pub.public_numbers().x.to_bytes(32, "big")),
            "y": b64(self.pub.public_numbers().y.to_bytes(32, "big")),
        }

    # ------------------------------------------------------------ crypto

    def _agent_jwt(self, ttl=300):
        """Signed statement of agency, verified by the cloud against our pubkey."""
        now = int(time.time())
        return pyjwt.encode(
            {"iss": self.agent_id, "sub": self.agent_id,
             "iat": now, "exp": now + ttl, "type": "agent"},
            self.key, algorithm="ES256")

    def _dpop_proof(self, method, url, access_token=None):
        ath = None
        if access_token:
            import hashlib, base64
            ath = base64.urlsafe_b64encode(
                hashlib.sha256(access_token.encode()).digest()
            ).rstrip(b"=").decode()
        payload = {"htm": method.upper(),
                   "url": url, "iat": int(time.time()),
                   "jti": "j_" + _rand()[:12]}
        if ath:
            payload["ath"] = ath
        # RFC 9449: the key (jwk) lives in the DPoP proof's JOSE header.
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._jwk}
        h = b64(json.dumps(header, separators=(",", ":")).encode())
        p = b64(json.dumps(payload, separators=(",", ":")).encode())
        signing = (h + "." + p).encode()
        sig = self.key.sign(signing, ec.ECDSA(hashes.SHA256()))
        return h + "." + p + "." + b64(sig)

    # ------------------------------------------------------------ grants

    def ensure_grant(self, site, scopes, wait=True):
        """Ask the cloud for access to `site`. Pushes approval to the user's
        phone; if `wait`, blocks until the user approves/denies (max ~5 min).
        Returns True if the grant is usable."""
        r = self.client.post(f"{self.base}/api/v1/authz-requests", json={
            "agent_id": self.agent_id, "site": site,
            "scopes": scopes, "agent_jwt": self._agent_jwt()})
        if r.status_code == 403:
            # grant already exists
            return self._try_token(site)
        if r.status_code == 409:
            return True
        r.raise_for_status()
        txn = r.json()["txn_id"]
        print(f"[surety] approval requested ({txn}) — waiting for phone…")
        if not wait:
            return None
        deadline = time.time() + 330
        while time.time() < deadline:
            p = self.client.get(f"{self.base}/api/v1/authz-requests/{txn}")
            if p.status_code >= 500:
                # transient server error — keep polling (the phone may still
                # respond), do not kill the whole flow over one bad poll
                time.sleep(self.poll_interval)
                continue
            p.raise_for_status()
            st = p.json()["status"]
            if st == "approved":
                print("[surety] approved ✓")
                return self._try_token(site)
            if st in ("denied", "expired"):
                print(f"[surety] {st}")
                raise SuretyError(f"approval {st} by user")
            time.sleep(self.poll_interval)
        raise SuretyError("approval timed out")

    def _try_token(self, site):
        try:
            self._get_access(site)
            return True
        except SuretyError:
            return False

    # ------------------------------------------------------------ tokens

    def _get_access(self, site, rotate=True):
        # self._access = (access_token, exp_float)
        if self._access and float(self._access[1]) > time.time() + 30:
            return self._access[0]
        if self._refresh:
            body = {"agent_id": self.agent_id, "site": site,
                    "agent_jwt": self._agent_jwt(),
                    "refresh_token": self._refresh}
            r = self.client.post(f"{self.base}/api/v1/token", json=body)
        else:
            body = {"agent_id": self.agent_id, "site": site,
                    "agent_jwt": self._agent_jwt()}
            r = self.client.post(f"{self.base}/api/v1/token", json=body)
        if r.status_code == 403:
            raise SuretyError("no grant — call ensure_grant() first")
        r.raise_for_status()
        d = r.json()
        import jwt as _j
        claims = _j.decode(d["access_token"], options={"verify_signature": False})
        exp = claims.get("exp")
        try:
            exp = float(exp) if exp is not None else time.time()
        except (TypeError, ValueError):
            exp = time.time()
        self._access = (d["access_token"], exp)
        self._refresh = d.get("refresh_token")
        return d["access_token"]

    # ------------------------------------------------------------ calls

    def request(self, method, url, stepup_action=None, **kwargs):
        """Perform an HTTP request through Surety: attaches Bearer + DPoP,
        auto-refreshes tokens, and on a 403 'stepup_required' from the site,
        requests a one-time step-up grant (phone prompt) and retries once."""
        site = url.split("/")[2].split(":")[0]
        at = self._get_access(site)
        for attempt in range(2):
            headers = kwargs.pop("headers", {})
            headers = dict(headers)
            headers["Authorization"] = f"Bearer {at}"
            headers["DPoP"] = self._dpop_proof(method, url, at)
            resp = self.client.request(method, url, headers=headers, **kwargs)
            if resp.status_code != 403 or not stepup_action:
                return resp
            ct = resp.headers.get("content-type", "")
            try:
                body = resp.json()
            except Exception:
                return resp
            # tolerate both the flat {"error": ...} and FastAPI's nested
            # {"detail": {"error": ...}} shapes
            err_obj = body.get("detail") if isinstance(body.get("detail"), dict) else body
            if err_obj.get("error") == "stepup_required":
                st = self._stepup(site, stepup_action)
                if not st:
                    return resp
                # retry with the one-time step-up token
                headers["X-Surety-Stepup"] = st
                return self.client.request(method, url, headers=headers, **kwargs)
            return resp
        raise SuretyError("unreachable")

    def _stepup(self, site, action):
        r = self.client.post(f"{self.base}/api/v1/stepup", json={
            "agent_id": self.agent_id, "site": site, "action": action,
            "agent_jwt": self._agent_jwt()})
        if r.status_code >= 400:
            print(f"[surety] stepup request failed: {r.text}")
            return None
        txn = r.json()["txn_id"]
        print(f"[surety] step-up requested ({txn}) — waiting for phone…")
        deadline = time.time() + 330
        while time.time() < deadline:
            p = self.client.get(f"{self.base}/api/v1/authz-requests/{txn}")
            if p.status_code >= 500:
                # transient server error — keep polling (the phone may still
                # respond), do not kill the whole flow over one bad poll
                time.sleep(self.poll_interval)
                continue
            p.raise_for_status()
            st = p.json()
            if st["status"] == "approved" and st.get("stepup_token"):
                print("[surety] step-up approved ✓")
                return st["stepup_token"]
            if st["status"] in ("denied", "expired"):
                print(f"[surety] step-up {st['status']}")
                return None
            time.sleep(self.poll_interval)
        return None


def _rand(n=16):
    import secrets
    return secrets.token_hex(n)


def b64(x: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
