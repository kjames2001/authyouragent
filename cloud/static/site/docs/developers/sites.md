# Accepting agents on your site

Your site receives HTTP requests from agents. Each request carries two headers:

- `Authorization: Bearer <access token>`: a signed pass saying which agent is acting, for which person, on your site, with which permissions. It lasts 10 minutes.
- `DPoP: <proof>`: a one-time signature made with the agent's private key over this exact method and URL. It proves that the caller holds the key the pass was issued to, so a copied pass is useless on its own.

A sensitive action also carries `X-AuthYourAgent-Stepup: <token>`, a one-time approval the person gave on their phone.

`SiteVerifier.verify()` checks all of this in one call.

## Set up the verifier

```python
from authyouragent import SiteVerifier, AuthError

verifier = SiteVerifier(
    "https://authyouragent.com",
    expected_audience="jobs.example.com",       # your site id
    public_base_url="https://jobs.example.com",  # the URL agents call
)
```

| Option | What it is for |
|---|---|
| `expected_audience` | Your site id. Agents request access to this exact name, and passes are only valid for it. Use your public hostname. With it set, the site also works at other addresses (a proxy, a local test server). |
| `public_base_url` | The public address agents call. The DPoP proof signs the full URL, so the verifier rebuilds it from this plus the request path. Set it whenever you run behind a proxy or under a path prefix. |
| `trust_forwarded` | Default `False`. Only if `public_base_url` is not set, `True` lets the verifier trust `X-Forwarded-Host` and `X-Forwarded-Proto`. Enable this only behind a proxy you control. |
| `mode` | `"cloud"` (default) or `"local"`. See below. |

`verify(request)` accepts any object with `.method`, `.url` and `.headers`. A FastAPI or Starlette `Request` works directly.

In JavaScript, `new SiteVerifier({expectedAudience, publicBaseUrl, mode})` and `await verifier.verify(request, {action})` do the same. It accepts a Fetch API `Request` (Cloudflare Workers, Next.js, Deno, Bun) or a Node/Express request, and returns `{agentId, agentName, userId, site, scopes, userInfo, stepup}`.

## Protect an endpoint

```python
@app.get("/api/jobs")
def list_jobs(request: Request):
    try:
        auth = verifier.verify(request)
    except AuthError as e:
        raise HTTPException(401, {"error": e.error})
    if "list" not in auth.scopes:
        raise HTTPException(403, {"error": "insufficient_scope"})
    return {"jobs": JOBS}
```

On success you get an `Auth` object:

| Field | Meaning |
|---|---|
| `agent_id`, `agent_name` | The agent acting. `agent_name` is filled in cloud mode only. |
| `user_id` | The person the agent acts for. Stable per person. |
| `site` | Your site id, as approved. |
| `scopes` | The permissions the person approved, as a list of strings. |
| `user_info` | Information about the person they agreed to share with you, for example `{"user:name": "Ada"}`. Empty unless you asked for it. |
| `stepup` | `True` if this request carried a valid one-time approval. |

Scopes are yours to define. Use short lowercase names (`list`, `apply`, `orders:read`); they are shown to the person as written.

## Sensitive actions (step-up)

For actions that should need a fresh approval every time, refuse the request unless `auth.stepup` is true, with this exact body:

```python
@app.post("/api/jobs/{job_id}/apply")
def apply(job_id: str, request: Request):
    if job_id not in JOBS_BY_ID:
        raise HTTPException(404, {"error": "no such job"})   # before verify, see below
    try:
        auth = verifier.verify(request)
    except AuthError as e:
        raise HTTPException(401, {"error": e.error})
    if "apply" not in auth.scopes:
        raise HTTPException(403, {"error": "insufficient_scope"})
    if not auth.stepup:
        raise HTTPException(403, {"error": "stepup_required"})
    ...
```

The Python agent SDK recognises `{"error": "stepup_required"}` (bare, or inside FastAPI's `detail`), asks the person, and retries with the approval.

**Do cheap checks before `verify()`.** A step-up approval is used up the moment `verify()` accepts it. If you then reject the request for another reason, such as a missing record, the person has to approve again.

## Asking for information about the person

An agent can request fields such as the person's name when it asks for access (`user_info=["user:name"]` in the access request). The person sees them on the approval card. If approved, the values arrive in `auth.user_info` on every request. The person can remove fields later; you then stop receiving them within 10 minutes.

Available fields: `user:name`, `user:email`, `user:phone` (only if they verified one).

## Cloud mode and local mode

**Cloud mode (default).** Each `verify()` makes one call to Auth Your Agent. Revocation applies to the very next request. Use this unless you have a reason not to.

**Local mode.** `SiteVerifier(..., mode="local")` checks the pass signature against the published signing keys and checks revocation against a signed list, both cached. No network call per request, except for step-up approvals, which are always confirmed with Auth Your Agent so they can be used once only.

| | Cloud mode | Local mode |
|---|---|---|
| Network call per request | Yes | No (step-up only) |
| Revocation takes effect | Next request | Within `rev_ttl` seconds (default 60) |
| If Auth Your Agent is unreachable | Requests are refused | Cached list used for up to `max_stale` seconds (default 5 × `rev_ttl`), then refused |

## Reporting an agent

If an agent misbehaves on your site, report it with any pass it presented (up to 7 days old):

```
POST /api/v1/reports
{"access_token": "<the agent's pass>", "kind": "abuse", "detail": "optional text"}
```

`kind` is one of `good`, `spam`, `abuse`, `fraud`, `policy`, `scraping`. Reports feed the agent's public reputation at `GET /api/v1/agents/{agent_id}/reputation`.

## Turning your API into agent tools

If your site has an OpenAPI description, you can generate an MCP server that exposes your endpoints as tools agents can call, with Auth Your Agent built in. See [MCP tools for your site](/docs/developers/mcp).
