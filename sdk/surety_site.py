"""surety_site — site-side SDK for the Surety cloud (vertical slice).

A site wants to accept agents acting on behalf of users. Two integration
styles are supported; both call the same cloud verify endpoint:

  1. SDK middleware (pulled trust):

     site = SuretySite(base_url="https://hermes.armadillo-lake.ts.net:8443")

     @app.post("/jobs/{job_id}/apply")
     def apply(job_id, req):
         auth = site.verify(req)          # raises SuretyAuthError
         if auth.stepup is False and auth.action == "apply":
             raise HTTPException(403, {"error": "stepup_required"})
         ...

  2. Hosted validation proxy (long tail): same verify() but the site points
     agent traffic through the cloud edge — the slice implements style 1;
     the proxy reuses this module behind a CNAME.

verify() performs the full three-part check against the cloud:
  1. access token signature (ES256, our JWKS) + issuer + audience
  2. DPoP proof: signature with the agent's registered key, htm/url/ath,
     jwk == registered pubkey (confused-deputy & token-theft defense)
  3. active grant for (agent, site) — or a one-time step-up token for
     high-risk actions (X-Surety-Stepup header)
"""

import base64
import hashlib
import json
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key


class SuretyAuthError(Exception):
    def __init__(self, error):
        super().__init__(error)
        self.error = error


class Auth:
    def __init__(self, d):
        self.agent_id = d.get("agent_id")
        self.agent_name = d.get("agent_name")
        self.user_id = d.get("user_id")
        self.site = d.get("site")
        self.scopes = d.get("scopes", [])
        self.stepup = d.get("stepup", False)


def _b64dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk_to_public_key(jwk):
    x = int.from_bytes(_b64dec(jwk["x"]), "big")
    y = int.from_bytes(_b64dec(jwk["y"]), "big")
    nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return nums.public_key()


def _jwk_thumbprint(jwk):
    ordered = {"crv": jwk.get("crv"), "kty": jwk.get("kty"),
               "x": jwk.get("x"), "y": jwk.get("y")}
    canonical = json.dumps(
        {k: ordered[k] for k in ("crv", "kty", "x", "y") if k in ordered},
        separators=(",", ":"), sort_keys=False)
    dig = hashlib.sha256(canonical.encode()).digest()
    return base64.urlsafe_b64encode(dig).rstrip(b"=").decode()


def _dpop_ok(proof_b64, expected_ath, method, url):
    """Verify a RFC 9449 DPoP proof with the SAME semantics as the cloud's
    verify_dpop: signature is ES256 over "<header>.<payload>" (JOSE), and
    htm/url/ath must match. Returns (jwk, ok, err)."""
    try:
        header_b64, payload_b64, sig_b64 = proof_b64.split(".")
        jwk = json.loads(_b64dec(header_b64)).get("jwk", {})
        claims = json.loads(_b64dec(payload_b64))
    except Exception:
        return None, False, "malformed dpop proof"
    if claims.get("htm") != method.upper():
        return jwk, False, "dpop htm mismatch"
    if _norm_url(claims.get("url")) != _norm_url(url):
        return jwk, False, "dpop url mismatch"
    iat = claims.get("iat", 0)
    if abs(time.time() - iat) > 120:
        return jwk, False, "dpop iat stale"
    ath = claims.get("ath")
    if ath and expected_ath and ath != expected_ath:
        return jwk, False, "dpop ath mismatch"
    if jwk.get("kty") != "EC":
        return jwk, False, "dpop jwk must be EC"
    try:
        pub = _jwk_to_public_key(jwk)
        sig = _b64dec(sig_b64)
        # the agent signs with ec.ECDSA(SHA256) -> r||s (NOT DER); the cloud's
        # verify_dpop verifies the raw r||s directly, so we must match it.
        pub.verify(sig, (header_b64 + "." + payload_b64).encode(),
                   ec.ECDSA(hashes.SHA256()))
    except Exception:
        return jwk, False, "dpop signature invalid"
    return jwk, True, None


def _norm_url(u):
    """Normalize a request URL for DPoP comparison: lowercase scheme+host,
    strip default ports — must mirror the cloud's _norm_dpop_url."""
    u = (u or "").strip()
    if "://" in u:
        pre, rest = u.split("://", 1)
        host, _, path = rest.partition("/")
        host = host.lower()
        if host.endswith(":443") and pre.lower() == "https":
            host = host[:-4]
        if host.endswith(":80") and pre.lower() == "http":
            host = host[:-3]
        u = f"{pre.lower()}://{host}" + (("/" + path) if path else "")
    return u


class SuretySite:
    def __init__(self, base_url, timeout=5.0, verify=True, mode="cloud",
                 rev_ttl=60):
        self.base = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, verify=verify)
        self.mode = mode            # "cloud" (strict, always to cloud) | "local" (hot path off cloud)
        self.rev_ttl = rev_ttl      # how long a signed revocation snapshot is trusted
        self._jwks = None
        self._jwks_at = 0
        self._rev = None            # decoded + signature-verified snapshot
        self._rev_at = 0

    # -------------------------------------------------- cache refresh
    def _refresh_jwks(self, force=False):
        if self._jwks and not force and (time.time() - self._jwks_at) < 3600:
            return self._jwks
        r = self.client.get(f"{self.base}/api/v1/jwks")
        r.raise_for_status()
        self._jwks = {k["kid"]: k for k in r.json()["keys"]}
        self._jwks_at = time.time()
        return self._jwks

    def _refresh_revocation(self, force=False):
        if self._rev and not force and (time.time() - self._rev_at) < self.rev_ttl:
            return self._rev
        r = self.client.get(f"{self.base}/api/v1/revocation")
        r.raise_for_status()
        snap = r.json()
        # the snapshot is signed with the same key as access tokens — verify
        # it against our JWKS so a forged/cached revocation list can't lie
        sig = snap["signature"]
        h = pyjwt.get_unverified_header(sig)
        jwks = self._refresh_jwks()
        key = jwks.get(h.get("kid"))
        if not key:
            raise SuretyAuthError("revocation snapshot: unknown JWKS kid")
        pub = _jwk_to_public_key(key)
        claims = pyjwt.decode(sig, pub, algorithms=["ES256"],
                              options={"verify_aud": False,
                                       "verify_iss": True,
                                       "issuer": self.base})
        # decoded claims must match the (unsigned) convenience fields
        if claims.get("rev_seq") != snap["rev_seq"]:
            raise SuretyAuthError("revocation snapshot: rev_seq mismatch")
        self._rev = {
            "iat": claims["iat"],
            "rev_seq": claims["rev_seq"],
            "agents": {a["id"]: a["flag"] for a in claims.get("revoked_agents", [])},
            "grants": {(g["agent"], g["site"]) for g in claims.get("revoked_grants", [])},
        }
        self._rev_at = time.time()
        return self._rev

    def pull_revocation(self):
        """§9.2 pull model: force-refresh the signed revocation snapshot so a
        site learns about a revocation. Cloud-mode sites verify live (always
        fresh); local-mode sites call this on their own interval. Returns the
        snapshot's rev_seq (monotonic — bumping it means state changed)."""
        snap = self._refresh_revocation(force=True)
        return snap.get("rev_seq", 0)

    # -------------------------------------------------- local verifier
    def verify_local(self, request, stepup_header=None):
        """Full local verification of an AYA agent request (hot path, §9.2).
        `request` needs .method, .url (absolute) and .headers. The access
        token's signature + DPoP binding are checked against the cached
        JWKS; grant/revocation is checked against the cached signed
        snapshot. Only the rare step-up single-use check falls back to the
        cloud. Returns Auth; raises SuretyAuthError on failure."""
        at = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
        dpop = request.headers.get("dpop")
        if not at or not dpop:
            raise SuretyAuthError("missing access token or DPoP proof")
        if stepup_header is None:
            stepup_header = request.headers.get("x-surety-stepup")

        # 1. access token: sig via JWKS + iss/aud/exp
        try:
            h = pyjwt.get_unverified_header(at)
            jwks = self._refresh_jwks()
            key = jwks.get(h.get("kid"))
            if not key:
                raise SuretyAuthError("unknown JWKS kid")
            pub = _jwk_to_public_key(key)
            at_claims = pyjwt.decode(at, pub, algorithms=["ES256"],
                                     audience=None, options={"verify_aud": False,
                                                             "verify_iss": True,
                                                             "issuer": self.base})
        except pyjwt.ExpiredSignatureError:
            raise SuretyAuthError("access token expired")
        except SuretyAuthError:
            raise
        except Exception as e:
            raise SuretyAuthError(f"access token invalid: {e}")

        # URL the CLIENT used (public), not the internal backend hop:
        # prefer X-Forwarded-Host/Host + X-Forwarded-Proto, like the cloud's
        # verifier does. Behind our vhost the request.url is the loopback hop.
        h = {k.lower(): v for k, v in dict(request.headers).items()}
        fwd_host = h.get("x-forwarded-host") or h.get("host") or ""
        fwd_proto = h.get("x-forwarded-proto") or ""
        if fwd_host:
            proto = fwd_proto or "https"
            path = str(request.url)
            if "://" in path:
                tail = path.split("://", 1)[1]
                path = "/" + tail.split("/", 1)[1] if "/" in tail else "/"
            else:
                path = path if path.startswith("/") else "/" + path
            url = f"{proto}://{fwd_host}{path}"
        else:
            url = str(request.url)
        aud = at_claims.get("aud")
        host = url.split("/")[2].split(":")[0] if "//" in url else url
        if aud not in (host, url):
            raise SuretyAuthError("audience mismatch")
        agent_id = at_claims.get("sub")

        # 2. DPoP: bind to the agent key + cnf
        ath = base64.urlsafe_b64encode(hashlib.sha256(at.encode()).digest()).rstrip(b"=").decode()
        jwk, ok, err = _dpop_ok(dpop, ath, request.method.upper(), url)
        if not ok:
            raise SuretyAuthError(f"DPoP: {err}")
        cnf = at_claims.get("cnf", {})
        if not cnf.get("dpop"):
            raise SuretyAuthError("access token lacks cnf binding")
        if _jwk_thumbprint(jwk) != cnf["dpop"]:
            raise SuretyAuthError("DPoP key != cnf-bound key")

        # 3. revocation snapshot (signed, cached)
        snap = self._refresh_revocation()
        flag = snap["agents"].get(agent_id, "ok")
        if flag != "ok":
            raise SuretyAuthError(f"agent {agent_id} globally {flag}")
        if (agent_id, aud) in snap["grants"]:
            raise SuretyAuthError("grant for site revoked")

        # 4. step-up (rare — single-use state lives in the cloud)
        stepup = False
        if stepup_header:
            ok2, err = self._verify_stepup(stepup_header, agent_id, aud)
            if not ok2:
                raise SuretyAuthError(f"step-up: {err}")
            stepup = True
        else:
            # a token whose scope implies a high-risk action should normally
            # carry a step-up; plain reads are fine without it.
            pass

        return Auth({"agent_id": agent_id, "user_id": at_claims.get("user"),
                     "site": aud, "scopes": at_claims.get("scope", []),
                     "stepup": stepup})

    def _verify_stepup(self, tok, agent_id, aud):
        try:
            h = pyjwt.get_unverified_header(tok)
            jwks = self._refresh_jwks()
            key = jwks.get(h.get("kid"))
            pub = _jwk_to_public_key(key)
            c = pyjwt.decode(tok, pub, algorithms=["ES256"],
                             options={"verify_aud": False,
                                      "verify_iss": True, "issuer": self.base})
        except Exception as e:
            return False, f"stepup token invalid: {e}"
        if c.get("type") != "stepup" or c.get("sub") != agent_id \
                or c.get("aud") not in (aud,):
            return False, "stepup token mismatch"
        # single-use state lives in the cloud (rare path)
        r = self._stepup_single_use(tok)
        if r and not r.get("valid"):
            return False, r.get("error", "stepup token used or expired")
        return True, None

    def _stepup_single_use(self, tok):
        r = self.client.post(f"{self.base}/api/v1/stepup/verify",
                             json={"stepup_token": tok}, timeout=5)
        try:
            return r.json()
        except Exception:
            return {"valid": False, "error": f"stepup cloud {r.status_code}"}

    def verify(self, request):
        """`request` is any object with .method, .url (absolute) and
        .headers (dict-like, case-insensitive) — e.g. a FastAPI/Starlette
        Request or a small shim. Dispatches on self.mode:
          • "local"  → verify_local(): hot path, no cloud round-trip
          • "cloud"  → POST /api/v1/verify (strict; default)
        Raises SuretyAuthError on any failure."""
        if self.mode == "local":
            return self.verify_local(request)
        return self._verify_cloud(request)

    def _verify_cloud(self, request):
        at = _auth_bearer(request.headers.get("authorization")
                          or request.headers.get("Authorization", ""))
        dpop = request.headers.get("dpop") or request.headers.get("DPoP", "")
        if not at or not dpop:
            raise SuretyAuthError("missing Bearer/DPoP credentials")
        body = {
            "access_token": at,
            "dpop": dpop,
            "method": request.method.upper(),
            "url": _abs_url(request),
        }
        stepup = (request.headers.get("x-surety-stepup")
                  or request.headers.get("X-Surety-Stepup"))
        if stepup:
            body["stepup_token"] = stepup
        r = self.client.post(f"{self.base}/api/v1/verify", json=body)
        if r.status_code != 200:
            raise SuretyAuthError(f"cloud unreachable: {r.status_code}")
        d = r.json()
        if not d.get("valid"):
            raise SuretyAuthError(d.get("error", "verification failed"))
        return Auth(d)

    def agent_status(self, agent_id):
        """Lightweight revocation pull (the 'pull' half of dual-path
        revocation). Returns {global_flag, revoked_sites}."""
        r = self.client.get(f"{self.base}/api/v1/agents/{agent_id}/status")
        if r.status_code == 404:
            raise SuretyAuthError("unknown agent")
        return r.json()


def _auth_bearer(h):
    if not h or " " not in h:
        return ""
    scheme, tok = h.split(" ", 1)
    return tok if scheme.lower() == "bearer" else ""


def _abs_url(request):
    """Return the absolute request URL the agent signed. Handles both a
    Starlette Request (whose .url is a URL object) and a shim that carries a
    plain absolute-string .url — don't double-prefix an already-absolute url."""
    u = getattr(request, "url", None)
    if u is None:
        return ""
    # already an absolute string (some site shims build one from the headers)
    if isinstance(u, str):
        return u
    # Starlette/FastAPI URL object -> rebuild from the forwarded scheme+host
    scheme = request.headers.get("x-forwarded-proto") or "https"
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
    path = getattr(u, "path", str(u))
    return f"{scheme}://{host}{path}"
