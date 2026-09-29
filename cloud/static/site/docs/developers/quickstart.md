# Developer quick start

Auth Your Agent has two sides. Pick the one you are building, or read both to see a full round trip.

- **An agent** asks a person for access to a site, then calls that site with a short-lived, key-bound pass. See [Building an agent](/docs/developers/agents).
- **A site** accepts those calls and checks each one. See [Accepting agents on your site](/docs/developers/sites).

The service is at `https://authyouragent.com`. There are SDKs for Python and for JavaScript/TypeScript; any other language works against the [HTTP API](/docs/developers/api).

## Install the SDK

| | Python | JavaScript / TypeScript |
|---|---|---|
| Package | `authyouragent` | `authyouragent` |
| Needs | Python 3.9+, `httpx`, `pyjwt`, `cryptography` | Node.js 18+, Deno, Bun or an edge runtime; no dependencies |
| Install (from the source tree, not yet on PyPI / npm) | `pip install ./sdk` | `npm install ./sdk-js` |

The examples on this page are Python. The same steps in JavaScript:

```js
import { AgentClient, SiteVerifier } from "authyouragent";

const agent = new AgentClient({ agentId: "ag_…", privateKeyPem });
await agent.ensureGrant("jobs.example.com", ["list", "apply"]);
const res = await agent.fetch("https://jobs.example.com/api/jobs");

const verifier = new SiteVerifier({ expectedAudience: "jobs.example.com",
                                    publicBaseUrl: "https://jobs.example.com" });
const who = await verifier.verify(request);   // throws AuthError
```

## 1. Give the agent a key

The agent makes its own key pair. The private half never leaves its machine.

```
python -m authyouragent keygen --name "Job-search assistant"
```

This prints JSON with `privkey_pem` and `jwk`. Save `privkey_pem` to a file on the agent's machine (below, `agent-key.pem`) and protect it like a password. `jwk` is the public half. The person who owns the agent opens [the app](/app), goes to **Your agents → New agent**, and pastes the `jwk`. The app returns an agent id such as `ag_1a2b3c…`.

## 2. The agent asks for access

```python
from authyouragent import AgentClient, AgentError

agent = AgentClient(
    base_url="https://authyouragent.com",
    agent_id="ag_1a2b3c…",
    privkey_pem=open("agent-key.pem").read(),
)

agent.ensure_grant("jobs.example.com", scopes=["list", "apply"])
```

`ensure_grant` sends the request to the person's phone and waits (up to about five and a half minutes) for them to approve. It returns `True` when access is ready and raises `AgentError` if they deny, it expires, or the agent was revoked. If access was already approved, it returns immediately.

## 3. The agent calls the site

```python
r = agent.request("GET", "https://jobs.example.com/api/jobs")
print(r.json())
```

`request` adds the `Authorization: Bearer …` pass and a fresh `DPoP` proof to every call, and renews the pass before it expires. It returns an ordinary `httpx.Response`.

For an action the site marks as sensitive, pass `stepup_action`:

```python
r = agent.request("POST", "https://jobs.example.com/api/jobs/j1/apply",
                  stepup_action="apply")
```

If the site answers `403` with `{"error": "stepup_required"}`, the SDK asks the person's phone again, then retries once with the one-time approval attached.

## 4. The site checks each call

```python
from authyouragent import SiteVerifier, AuthError

verifier = SiteVerifier("https://authyouragent.com",
                        expected_audience="jobs.example.com",
                        public_base_url="https://jobs.example.com")

@app.get("/api/jobs")
def jobs(request: Request):
    try:
        auth = verifier.verify(request)
    except AuthError as e:
        raise HTTPException(401, {"error": e.error})
    if "list" not in auth.scopes:
        raise HTTPException(403, {"error": "insufficient_scope"})
    return {"jobs": [...], "for_user": auth.user_id, "agent": auth.agent_name}
```

That is the whole integration. The [site guide](/docs/developers/sites) covers sensitive actions, local verification and user information.

## Complete examples

- `sdk/examples/agent.py`: an agent that asks for access, lists jobs and applies to one.
- `sdk/examples/site_fastapi.py`: a site that accepts it.
- `sdk-js/README.md`: the same in JavaScript, including a Cloudflare Worker.
- `demo/app.py`: the reference job board the test suites run against.
