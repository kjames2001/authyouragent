"""authyouragent.site — site-side SDK for the Auth Your Agent cloud (vertical slice).

A site wants to accept agents acting on behalf of users. Two integration
styles are supported; both call the same cloud verify endpoint:

  1. SDK middleware (pulled trust):

     site = SiteVerifier(base_url="https://hermes.armadillo-lake.ts.net:8443")

     @app.post("/jobs/{job_id}/apply")
     def apply(job_id, req):
         auth = site.verify(req)          # raises AuthError
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
     high-risk actions (X-AuthYourAgent-Stepup header)
"""

import base64
import hashlib
import hmac
import json
import threading
import time

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


class AuthError(Exception):
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
        # v19: the user-info fields the user consented to sharing with THIS
        # site (values, e.g. {"user:email": "...", "user:name": "..."}).
        # Empty dict when the grant declares none or the user has no value.
        self.user_info = d.get("user_info", {})


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


DPOP_WINDOW = 120        # seconds: |now - iat| accepted (mirrors the cloud)
DPOP_SKEW = 10           # extra slack on the replay-cache TTL


class _JtiCache:
    """Thread-safe TTL set of (jkt, jti) seen within the DPoP iat window.
    In-process only: a multi-worker site needs a shared store (redis) for
    cross-worker replay protection."""

    def __init__(self):
        self._seen = {}
        self._lock = threading.Lock()
        self._n = 0

    def add_once(self, key, expires_at):
        """Record `key`; False if it was already seen and not yet expired."""
        now = time.time()
        with self._lock:
            self._n += 1
            if self._n % 256 == 0 or len(self._seen) > 50000:
                for k in [k for k, e in self._seen.items() if e <= now]:
                    del self._seen[k]
            e = self._seen.get(key)
            if e is not None and e > now:
                return False
            self._seen[key] = expires_at
            return True


def _dpop_ok(proof_b64, expected_ath, method, url, replay=None):
    """Verify a RFC 9449 DPoP proof with the SAME semantics as the cloud's
    verify_dpop: signature is ES256 over "<header>.<payload>" (JOSE, raw
    r||s — whatever the agent's ec.ECDSA sign emits, verified identically),
    and htm/url(htu)/iat/ath must match. `expected_ath` is MANDATORY: the
    proof accompanies an access token, so it must carry the token's hash.
    `replay` (a _JtiCache) rejects a (jkt, jti) seen within the window.
    Returns (jwk, ok, err)."""
    try:
        header_b64, payload_b64, sig_b64 = proof_b64.split(".")
        header = json.loads(_b64dec(header_b64))
        claims = json.loads(_b64dec(payload_b64))
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError("not an object")
        jwk = header.get("jwk", {})
        if not isinstance(jwk, dict):
            raise ValueError("jwk not an object")
    except Exception:
        return None, False, "malformed dpop proof"
    if header.get("typ") != "dpop+jwt":
        return jwk, False, "dpop typ must be dpop+jwt"
    if header.get("alg") != "ES256":
        return jwk, False, "dpop alg must be ES256"
    if claims.get("htm") != method.upper():
        return jwk, False, "dpop htm mismatch"
    # RFC 9449 names the claim 'htu'; the Auth Your Agent cloud historically used 'url'.
    # Accept either, but if both are present they must agree.
    htu, u = claims.get("htu"), claims.get("url")
    if htu is not None and u is not None and _norm_url(htu) != _norm_url(u):
        return jwk, False, "dpop htu/url disagree"
    signed_url = htu if htu is not None else u
    if not signed_url or _norm_url(signed_url) != _norm_url(url):
        return jwk, False, "dpop url mismatch"
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or abs(time.time() - iat) > DPOP_WINDOW:
        return jwk, False, "dpop iat stale"
    jti = claims.get("jti")
    if not jti or not isinstance(jti, str):
        return jwk, False, "dpop jti missing"
    if not expected_ath:
        return jwk, False, "dpop ath required"
    ath = claims.get("ath")
    if not ath:
        return jwk, False, "dpop ath missing"
    if not hmac.compare_digest(str(ath), expected_ath):
        return jwk, False, "dpop ath mismatch"
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return jwk, False, "dpop jwk must be EC P-256"
    try:
        pub = _jwk_to_public_key(jwk)
        sig = _b64dec(sig_b64)
        # JWS ES256 is raw r||s (RFC 7518 §3.4); agents built with SDK <= 0.2
        # sent DER. Accept both, like the cloud's verify_dpop.
        if len(sig) == 64:
            sig = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                       int.from_bytes(sig[32:], "big"))
        pub.verify(sig, (header_b64 + "." + payload_b64).encode(),
                   ec.ECDSA(hashes.SHA256()))
    except Exception:
        return jwk, False, "dpop signature invalid"
    # replay check LAST: only a fully valid proof burns its jti
    if replay is not None:
        key = (_jwk_thumbprint(jwk), jti)
        if not replay.add_once(key, max(iat, time.time()) + DPOP_WINDOW + DPOP_SKEW):
            return jwk, False, "dpop proof replayed"
    return jwk, True, None


def _norm_url(u):
    """Normalize a request URL for DPoP comparison: lowercase scheme+host,
    strip default ports — must mirror the cloud's _norm_dpop_url."""
    u = (u or "").strip() if isinstance(u, str) else ""
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


def _req_path(request):
    """Path component of the request (no query), from a Starlette URL
    object, an absolute string URL, or a bare path string."""
    u = getattr(request, "url", None)
    if u is None:
        return "/"
    p = getattr(u, "path", None)
    if isinstance(p, str):
        return p or "/"
    u = str(u)
    if "://" in u:
        tail = u.split("://", 1)[1]
        u = "/" + tail.split("/", 1)[1] if "/" in tail else "/"
    u = u.split("?", 1)[0].split("#", 1)[0]
    return u if u.startswith("/") else "/" + u


class SiteVerifier:
    def __init__(self, base_url, timeout=5.0, verify=True, mode="cloud",
                 rev_ttl=60, issuer=None, expected_audience=None,
                 public_base_url=None, trust_forwarded=False, max_stale=None):
        """
        base_url          the Auth Your Agent cloud (JWKS/revocation/verify endpoints)
        issuer            expected 'iss' of access/step-up tokens and the
                          revocation snapshot (default: base_url — the cloud
                          signs with AUTHYOURAGENT_ISS, which equals its public base)
        expected_audience this site's id (the token 'aud'); when set, aud is
                          compared to it instead of the request's Host
        public_base_url   the public URL agents sign DPoP proofs against
                          (e.g. https://host:8443/jobboard); the expected
                          DPoP URL = its origin + request path (its path
                          prefix is added only if the routed path lacks it)
        trust_forwarded   only when True (and no public_base_url) are the
                          client-controllable X-Forwarded-Host/Proto used
        max_stale         max age (s) of a revocation snapshot used when a
                          refresh FAILS; beyond it verification fails closed
                          (default 5*rev_ttl)
        """
        self.base = base_url.rstrip("/")
        self.issuer = (issuer or self.base).rstrip("/")
        self.client = httpx.Client(timeout=timeout, verify=verify)
        self.mode = mode            # "cloud" (strict, always to cloud) | "local" (hot path off cloud)
        self.rev_ttl = rev_ttl      # how long a signed revocation snapshot is trusted
        self.max_stale = max_stale if max_stale is not None else 5 * rev_ttl
        self.expected_audience = expected_audience
        self.public_base_url = public_base_url.rstrip("/") if public_base_url else None
        self.trust_forwarded = trust_forwarded
        self._jwks = None
        self._jwks_at = 0
        self._rev = None            # decoded + signature-verified snapshot
        self._rev_at = 0
        self._cache_lock = threading.RLock()   # guards JWKS + snapshot refresh
        self._jti = _JtiCache()

    # -------------------------------------------------- request URL / aud
    def expected_url(self, request):
        """The absolute URL the agent must have signed in its DPoP proof."""
        path = _req_path(request)
        if self.public_base_url:
            pb = self.public_base_url
            if "://" in pb:
                scheme, rest = pb.split("://", 1)
                host, _, bpath = rest.partition("/")
                origin = f"{scheme}://{host}"
                bpath = ("/" + bpath).rstrip("/") if bpath else ""
            else:
                origin, bpath = pb, ""
            # routed path already carries the mount prefix (our caddy does not
            # strip /jobboard) -> don't double it; a prefix-stripping proxy ->
            # re-add it
            if bpath and not (path == bpath or path.startswith(bpath + "/")):
                path = bpath + path
            return origin + path
        hdr = request.headers
        host = ""
        proto = ""
        if self.trust_forwarded:
            host = hdr.get("x-forwarded-host") or ""
            proto = hdr.get("x-forwarded-proto") or ""
        host = host or hdr.get("host") or ""
        if not host:
            u = getattr(request, "url", None)
            if isinstance(u, str) and "://" in u:
                return u.split("?", 1)[0]
            raise AuthError("cannot determine request URL")
        return f"{proto or 'https'}://{host}{path}"

    def _check_aud(self, aud, url):
        if self.expected_audience is not None:
            if aud != self.expected_audience:
                raise AuthError("audience mismatch")
            return
        host = url.split("/")[2].split(":")[0] if "//" in url else url
        if aud not in (host, url):
            raise AuthError("audience mismatch")

    # -------------------------------------------------- cache refresh
    def _refresh_jwks(self, force=False):
        with self._cache_lock:
            return self._refresh_jwks_locked(force)

    def _refresh_jwks_locked(self, force=False):
        if self._jwks and not force and (time.time() - self._jwks_at) < 3600:
            return self._jwks
        try:
            r = self.client.get(f"{self.base}/api/v1/jwks")
        except httpx.HTTPError as e:
            if force or not self._jwks:
                raise AuthError(f"cloud unreachable: {e}")
            return self._jwks          # stale JWKS beats a crash (local mode)
        if r.status_code != 200:
            if force or not self._jwks:
                raise AuthError(f"cloud unreachable: {r.status_code}")
            return self._jwks
        try:
            self._jwks = {k["kid"]: k for k in r.json()["keys"]}
        except Exception as e:
            if force or not self._jwks:
                raise AuthError(f"JWKS malformed: {e}")
            return self._jwks
        self._jwks_at = time.time()
        return self._jwks

    def _refresh_revocation(self, force=False):
        with self._cache_lock:
            return self._refresh_revocation_locked(force)

    def _stale_or_fail(self, why):
        """A refresh failed: use the cached snapshot only while it is young
        enough; otherwise fail CLOSED (a site cut off from the cloud must
        not keep honoring revoked agents forever)."""
        if not self._rev:
            raise AuthError(f"revocation snapshot unavailable: {why}")
        if time.time() - self._rev["iat"] > self.max_stale:
            raise AuthError(f"revocation snapshot too stale: {why}")
        return self._rev

    def _refresh_revocation_locked(self, force=False):
        if self._rev and not force and (time.time() - self._rev_at) < self.rev_ttl:
            return self._rev
        try:
            r = self.client.get(f"{self.base}/api/v1/revocation")
        except httpx.HTTPError as e:
            if force:
                raise AuthError(f"cloud unreachable: {e}")
            return self._stale_or_fail(f"cloud unreachable: {e}")
        if r.status_code != 200:
            if force:
                raise AuthError(f"cloud unreachable: {r.status_code}")
            return self._stale_or_fail(f"cloud {r.status_code}")
        try:
            snap = r.json()
            # the snapshot is signed with the same key as access tokens —
            # verify it against our JWKS so a forged revocation list can't lie
            sig = snap["signature"]
            h = pyjwt.get_unverified_header(sig)
            # force the JWKS too: after a key rotation the snapshot is signed
            # with the NEW kid, and a stale 1h-cached JWKS would reject it
            jwks = self._refresh_jwks_locked(force=force)
            key = jwks.get(h.get("kid"))
            if not key:
                raise AuthError("revocation snapshot: unknown JWKS kid")
            pub = _jwk_to_public_key(key)
            claims = pyjwt.decode(sig, pub, algorithms=["ES256"],
                                  issuer=self.issuer,
                                  options={"verify_aud": False,
                                           "require": ["iss", "iat"]})
            # decoded claims must match the (unsigned) convenience fields
            if claims.get("rev_seq") != snap["rev_seq"]:
                raise AuthError("revocation snapshot: rev_seq mismatch")
            rev = {
                "iat": float(claims["iat"]),
                "rev_seq": claims["rev_seq"],
                "agents": {a["id"]: a["flag"] for a in claims.get("revoked_agents", [])},
                "grants": {(g["agent"], g["site"]) for g in claims.get("revoked_grants", [])},
            }
        except AuthError:
            raise
        except Exception as e:
            raise AuthError(f"revocation snapshot invalid: {e}")
        self._rev = rev
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
        """Full local verification of an Auth Your Agent agent request (hot path, §9.2).
        `request` needs .method, .url and .headers. The access token's
        signature + DPoP binding are checked against the cached JWKS;
        grant/revocation against the cached signed snapshot. Only the rare
        step-up single-use check goes to the cloud. Returns Auth; raises
        AuthError on failure."""
        at = (request.headers.get("authorization") or "")
        if at.lower().startswith("bearer "):
            at = at[7:].strip()
        else:
            at = ""
        dpop = request.headers.get("dpop")
        if not at or not dpop:
            raise AuthError("missing access token or DPoP proof")
        if stepup_header is None:
            stepup_header = request.headers.get("x-authyouragent-stepup")

        # 1. access token: sig via JWKS + iss/exp (+ aud below)
        try:
            h = pyjwt.get_unverified_header(at)
            jwks = self._refresh_jwks()
            key = jwks.get(h.get("kid"))
            if not key:
                raise AuthError("unknown JWKS kid")
            pub = _jwk_to_public_key(key)
            # NB: pyjwt only checks iss when `issuer=` is a kwarg — putting it
            # in options={} is silently ignored
            at_claims = pyjwt.decode(at, pub, algorithms=["ES256"],
                                     issuer=self.issuer,
                                     options={"verify_aud": False,
                                              "require": ["iss", "exp", "sub", "aud"]})
        except pyjwt.ExpiredSignatureError:
            raise AuthError("access token expired")
        except AuthError:
            raise
        except Exception as e:
            raise AuthError(f"access token invalid: {e}")
        # access tokens carry no 'type' today (step-up tokens say "stepup");
        # accept an explicit "access" should the cloud add one
        if at_claims.get("type") not in (None, "access"):
            raise AuthError("not an access token")

        url = self.expected_url(request)
        aud = at_claims.get("aud")
        self._check_aud(aud, url)
        agent_id = at_claims.get("sub")

        # 2. DPoP: bind to the agent key + cnf (ath mandatory, jti single-use)
        ath = base64.urlsafe_b64encode(hashlib.sha256(at.encode()).digest()).rstrip(b"=").decode()
        cnf = at_claims.get("cnf") or {}
        if not isinstance(cnf, dict) or not cnf.get("dpop"):
            raise AuthError("access token lacks cnf binding")
        jwk, ok, err = _dpop_ok(dpop, ath, request.method.upper(), url,
                                replay=self._jti)
        if not ok:
            raise AuthError(f"DPoP: {err}")
        if _jwk_thumbprint(jwk) != cnf["dpop"]:
            raise AuthError("DPoP key != cnf-bound key")

        # 3. revocation snapshot (signed, cached; fails closed when too stale)
        snap = self._refresh_revocation()
        flag = snap["agents"].get(agent_id, "ok")
        if flag != "ok":
            raise AuthError(f"agent {agent_id} globally {flag}")
        if (agent_id, aud) in snap["grants"]:
            raise AuthError("grant for site revoked")

        # 4. step-up (rare — single-use state lives in the cloud)
        stepup = False
        if stepup_header:
            ok2, err = self._verify_stepup(stepup_header, agent_id, aud)
            if not ok2:
                raise AuthError(f"step-up: {err}")
            stepup = True

        return Auth({"agent_id": agent_id, "user_id": at_claims.get("user"),
                     "site": aud, "scopes": at_claims.get("scope", []),
                     "user_info": at_claims.get("user_info", {}),
                     "stepup": stepup})

    def _verify_stepup(self, tok, agent_id, aud):
        try:
            h = pyjwt.get_unverified_header(tok)
            jwks = self._refresh_jwks()
            key = jwks.get(h.get("kid"))
            if not key:
                return False, "stepup token: unknown JWKS kid"
            pub = _jwk_to_public_key(key)
            c = pyjwt.decode(tok, pub, algorithms=["ES256"],
                             issuer=self.issuer,
                             options={"verify_aud": False,
                                      "require": ["iss", "exp", "sub", "aud"]})
        except Exception as e:
            return False, f"stepup token invalid: {e}"
        if c.get("type") != "stepup" or c.get("sub") != agent_id \
                or c.get("aud") != aud:
            return False, "stepup token mismatch"
        # single-use state lives in the cloud (rare path)
        r = self._stepup_single_use(tok)
        if not isinstance(r, dict) or r.get("valid") is not True:
            err = r.get("error") if isinstance(r, dict) else None
            return False, err or "stepup token used or expired"
        return True, None

    def _stepup_single_use(self, tok):
        try:
            r = self.client.post(f"{self.base}/api/v1/stepup/verify",
                                 json={"stepup_token": tok}, timeout=5)
        except httpx.HTTPError as e:
            return {"valid": False, "error": f"stepup cloud unreachable: {e}"}
        if r.status_code != 200:
            return {"valid": False, "error": f"stepup cloud {r.status_code}"}
        try:
            return r.json()
        except Exception:
            return {"valid": False, "error": f"stepup cloud {r.status_code}"}

    def verify(self, request):
        """`request` is any object with .method, .url and .headers
        (dict-like, case-insensitive) — e.g. a FastAPI/Starlette Request or
        a small shim. Dispatches on self.mode:
          • "local"  → verify_local(): hot path, no cloud round-trip
          • "cloud"  → POST /api/v1/verify (strict; default)
        Raises AuthError on any failure."""
        if self.mode == "local":
            return self.verify_local(request)
        return self._verify_cloud(request)

    def _verify_cloud(self, request):
        at = _auth_bearer(request.headers.get("authorization")
                          or request.headers.get("Authorization", ""))
        dpop = request.headers.get("dpop") or request.headers.get("DPoP", "")
        if not at or not dpop:
            raise AuthError("missing Bearer/DPoP credentials")
        body = {
            "access_token": at,
            "dpop": dpop,
            "method": request.method.upper(),
            "url": self.expected_url(request),
        }
        stepup = (request.headers.get("x-authyouragent-stepup")
                  or request.headers.get("X-AuthYourAgent-Stepup"))
        if stepup:
            body["stepup_token"] = stepup
        if self.expected_audience is not None:
            body["site"] = self.expected_audience
        try:
            r = self.client.post(f"{self.base}/api/v1/verify", json=body)
        except httpx.HTTPError as e:
            raise AuthError(f"cloud unreachable: {e}")
        if r.status_code != 200:
            raise AuthError(f"cloud unreachable: {r.status_code}")
        try:
            d = r.json()
        except Exception:
            raise AuthError("cloud returned non-JSON")
        if not isinstance(d, dict) or d.get("valid") is not True:
            raise AuthError((d.get("error") if isinstance(d, dict) else None)
                                  or "verification failed")
        if self.expected_audience is not None and d.get("site") != self.expected_audience:
            raise AuthError("audience mismatch")
        return Auth(d)

    def agent_status(self, agent_id):
        """Lightweight revocation pull (the 'pull' half of dual-path
        revocation). Returns {global_flag, revoked_sites}."""
        try:
            r = self.client.get(f"{self.base}/api/v1/agents/{agent_id}/status")
        except httpx.HTTPError as e:
            raise AuthError(f"cloud unreachable: {e}")
        if r.status_code == 404:
            raise AuthError("unknown agent")
        if r.status_code != 200:
            raise AuthError(f"cloud {r.status_code}")
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
