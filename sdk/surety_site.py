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


class SuretySite:
    def __init__(self, base_url, timeout=5.0, verify=True):
        self.base = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, verify=verify)

    def verify(self, request):
        """`request` is any object with .method, .url (absolute) and
        .headers (dict-like, case-insensitive) — e.g. a FastAPI/Starlette
        Request or a small shim. Raises SuretyAuthError."""
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
