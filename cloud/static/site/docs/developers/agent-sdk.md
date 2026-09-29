# Building an agent

An agent needs three things: its own key, the person's approval for each site, and a way to sign every request it makes. The Python SDK does all three.

## The agent's key

```
python -m authyouragent keygen --name "Job-search assistant"
```

Output (shortened):

```json
{
  "agent_key": {
    "name": "Job-search assistant",
    "jwk": {"kty": "EC", "crv": "P-256", "x": "…", "y": "…"},
    "pubkey_pem": "-----BEGIN PUBLIC KEY-----…",
    "privkey_pem": "-----BEGIN PRIVATE KEY-----…"
  }
}
```

- `privkey_pem` stays on the agent's machine. Anyone with it can act as the agent, within what the person approved. Store it the way you store any secret.
- `jwk` goes to the person, who pastes it into **Your agents → New agent** in the app. The app returns the agent id (`ag_…`).

Auth Your Agent never sees the private key. You can also generate the key yourself: any EC P-256 key pair works; register the public key as a JWK or PEM.

## Create the client

```python
from authyouragent import AgentClient

agent = AgentClient(
    base_url="https://authyouragent.com",
    agent_id="ag_1a2b3c…",
    privkey_pem=PRIVATE_KEY_PEM,
    poll_interval=1.5,   # seconds between checks while waiting for approval
    timeout=60,          # HTTP timeout, seconds
)
```

One client can talk to many sites. It keeps a separate pass for each site, because a pass is only valid for the site it was issued for.

## Ask for access

```python
agent.ensure_grant("jobs.example.com", scopes=["list", "apply"])
```

- `site` is the site's id, normally its hostname. The site documents it.
- `scopes` are the permissions you want, as the site names them: 1 to 20 strings of lowercase letters, digits and `_ : . -`.

The person receives the request on their phone. `ensure_grant`:

- returns `True` as soon as they approve
- returns `True` immediately if access is already approved
- raises `AgentError` if they deny, if the request expires (5 minutes), or if they revoked the agent
- with `wait=False`, returns `None` right after sending the request, without waiting

Only one request per site can be waiting at a time.

If the agent restarts within an hour of the approval, `ensure_grant` picks the access up again without asking the person twice.

## Make requests

```python
r = agent.request("GET", "https://jobs.example.com/api/jobs", params={"remote": 1})
```

`request(method, url, stepup_action=None, site=None, **kwargs)` accepts the same keyword arguments as `httpx` (`json=`, `params=`, `headers=` and so on) and returns an `httpx.Response`. For every call it:

`site` is the site id you were granted. It defaults to the URL's host; pass it when you reach the site at another address, as in the [walkthrough](/docs/developers/walkthrough).

1. picks the pass for the URL's host, renewing it if it expires within 30 seconds
2. adds `Authorization: Bearer <pass>` and a fresh `DPoP` proof for this method and URL

The site id is taken from the URL's hostname, so the hostname you call must be the site id you asked access for.

## Sensitive actions

```python
r = agent.request("POST", "https://jobs.example.com/api/jobs/j1/apply",
                  json={"cover_letter": "…"}, stepup_action="apply")
```

If the site replies `403` with `stepup_required`, the SDK:

1. asks the person's phone to approve `apply` on that site
2. waits for the answer (up to about five and a half minutes)
3. retries the request once, with the one-time approval in `X-AuthYourAgent-Stepup`

If the person denies, or doesn't answer in time, you get the original `403` response back. Without `stepup_action`, the SDK never asks for a step-up and returns the `403` as is.

A step-up approval can be used once, within 60 seconds of being granted.

## Errors

Everything the SDK raises is an `AgentError`, with a message you can show or log:

| Message starts with | Meaning |
|---|---|
| `approval denied by user`, `approval expired by user` | The person said no, or didn't answer within 5 minutes. |
| `agent revoked by owner` | The person blocked this agent. Stop and tell your user. |
| `no grant — call ensure_grant() first` | No approved access for this site, or it was revoked. |
| `cloud unreachable` | Network problem reaching Auth Your Agent. Safe to retry. |

Responses from the site itself (for example a `404`) are returned, not raised.

## JavaScript and TypeScript

The JavaScript SDK has the same shape: `new AgentClient({agentId, privateKeyPem})`, `await agent.ensureGrant(site, scopes, {userInfo})` and `await agent.fetch(url, {method, stepupAction})`, which returns a standard `Response`. It can also make the key: `await keygen()` returns `{privateKeyPem, jwk}`. Errors are `AgentError` with a `code` of `denied`, `expired`, `timeout`, `revoked` or `no_grant`.

## When the agent is stuck at a login

If a site has no Auth Your Agent support and your agent reaches a login, CAPTCHA or 2FA page, it can ask its owner to take over the browser from their phone. MCP agents need no code: add the `authyouragent-mcp` server (`pip install "authyouragent[mcp]"`). See [Take over](/docs/developers/takeover).

## Other languages

The SDKs are a thin layer over the [HTTP API](/docs/developers/api): an agent JWT signed with the agent key proves the agent's identity to Auth Your Agent, and DPoP proofs (RFC 9449) sign each request to the site. Any language with ES256 support can do the same.
