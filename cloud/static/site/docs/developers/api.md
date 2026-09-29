# HTTP API reference

Base URL: `https://authyouragent.com`. Bodies are JSON. Errors are `{"detail": "<message>"}` with a 4xx status, except the verify endpoints, which always answer `200` with `{"valid": false, "error": "…"}` on failure.

The SDKs call these for you. Use this page to integrate from another language or to debug.

## Signatures and keys

All tokens are JWTs signed with ES256 (ECDSA P-256 with SHA-256).

**Agent JWT.** Proves to Auth Your Agent that the caller holds the agent's private key. Signed with the agent key.

| Claim | Value |
|---|---|
| `iss`, `sub` | the agent id |
| `iat`, `exp` | issue and expiry time; at most 900 seconds apart |
| `type` | `"agent"` |

**DPoP proof** (RFC 9449). Proves to a site that the caller holds the key a pass was issued to. One per request, signed with the agent key.

| Part | Value |
|---|---|
| header `typ` / `alg` | `dpop+jwt` / `ES256` |
| header `jwk` | the agent's public key (EC P-256) |
| `htm` | HTTP method, upper case |
| `htu` | full request URL (scheme, host, path; default port omitted) |
| `iat` | now, integer seconds; accepted within 120 seconds |
| `jti` | unique, 8–128 characters; each value is accepted once |
| `ath` | base64url SHA-256 of the access token |

**Access token ("pass").** Issued by Auth Your Agent, signed with a key published at `/api/v1/jwks`.

| Claim | Value |
|---|---|
| `iss` | `https://authyouragent.com` |
| `sub` | agent id |
| `aud` | site id |
| `user` | the person's user id |
| `scope` | approved scopes, list |
| `user_info` | approved information about the person, if any |
| `cnf.dpop` | JWK thumbprint (RFC 7638) of the agent key |
| `type` | `"access"` |
| `exp` | 10 minutes after issue, or the grant's own expiry if sooner |

**Step-up token.** Same signature. `type` is `"stepup"`, `act` lists the approved action, and it is valid for 60 seconds and one use.

## Agent endpoints

### POST /api/v1/authz-requests

Ask the person for access to a site.

```json
{"agent_id": "ag_…", "site": "jobs.example.com",
 "scopes": ["list", "apply"], "user_info": ["user:name"],
 "agent_jwt": "<agent JWT>"}
```

- `200` → `{"txn_id": "t_…", "expires_in": 300}`
- `409` → access is already approved, or a request for this site is already waiting
- `403` → the agent was revoked by its owner
- `400` → invalid scopes (1–20 strings of `[a-z0-9_:.-]`, up to 64 characters each) or unknown `user_info` field

### GET /api/v1/authz-requests/{txn_id}

Check a request.

```json
{"status": "pending", "agent": "Job-search assistant", "site": "jobs.example.com",
 "scopes": ["list", "apply"], "user_info": ["user:name"]}
```

`status` is `pending`, `approved`, `denied`, `expired` or `consumed`. For an approved step-up, send header `X-Agent-JWT: <agent JWT>` to receive `stepup_token`; without it, `stepup_token_error` explains why it is missing.

### POST /api/v1/token

Get or renew a pass.

```json
{"agent_id": "ag_…", "site": "jobs.example.com", "agent_jwt": "<agent JWT>",
 "refresh_token": "<optional>"}
```

```json
{"access_token": "…", "token_type": "DPoP", "expires_in": 600,
 "refresh_token": "…", "scope": ["list", "apply"],
 "grant_expires_at": null, "grant_uses_left": null}
```

Without `refresh_token`, this works within one hour of the person's approval. Every call returns a new refresh token and invalidates the previous one.

- `403` → no approved access for this site
- `401` → refresh token already used or invalid

### POST /api/v1/stepup

Ask the person to approve one sensitive action.

```json
{"agent_id": "ag_…", "site": "jobs.example.com", "action": "apply",
 "agent_jwt": "<agent JWT>"}
```

→ `{"txn_id": "t_…", "expires_in": 300}`. Then poll `GET /api/v1/authz-requests/{txn_id}` with `X-Agent-JWT`. Requires approved access to the site (`403` otherwise).

## Site endpoints

### POST /api/v1/verify

Check an incoming agent request (cloud mode). Consumes the step-up token if one is sent.

```json
{"access_token": "…", "dpop": "…", "method": "POST",
 "url": "https://jobs.example.com/api/jobs/j1/apply",
 "stepup_token": "<optional>", "site": "jobs.example.com", "action": "apply"}
```

```json
{"valid": true, "agent_id": "ag_…", "agent_name": "Job-search assistant",
 "user_id": "u_…", "site": "jobs.example.com", "scopes": ["list", "apply"],
 "user_info": {"user:name": "Ada"}, "stepup": true}
```

`site` is your site id. When given, the pass must be for exactly that site, and the `url` may be any address your site is reached at (a proxy or a test server); the DPoP proof still has to match that `url`. Without `site`, the pass must be for the `url`'s host. `action` rejects a step-up approved for a different action. Both are optional but recommended.

### GET /api/v1/jwks

The public keys that sign passes, step-up tokens and revocation lists. Several may be listed during a key rotation; select by `kid`.

### GET /api/v1/revocation

Signed revocation list for local verification.

```json
{"signature": "<JWT>", "rev_seq": 42,
 "revoked_agents": [{"id": "ag_…", "flag": "revoked"}],
 "revoked_grants": [{"agent": "ag_…", "site": "jobs.example.com"}]}
```

Trust only the contents of `signature` (a JWT, `type: "revocation"`), verified against `/api/v1/jwks`.

### POST /api/v1/stepup/verify

Use up a step-up token (local mode).

```json
{"stepup_token": "…", "site": "jobs.example.com", "action": "apply"}
```

→ `{"valid": true, "agent_id": "…", "user_id": "…", "site": "…", "actions": ["apply"]}`. A second call with the same token returns `{"valid": false, "error": "stepup token used or expired"}`.

### POST /api/v1/reports

Report an agent's behaviour.

```json
{"access_token": "<a pass the agent presented, up to 7 days old>",
 "kind": "abuse", "detail": "optional"}
```

`kind`: `good`, `spam`, `abuse`, `fraud`, `policy`, `scraping`.

### GET /api/v1/agents/{agent_id}/status

`{"global_flag": "ok", "revoked_sites": ["…"], "jwks_url": "…"}`. `global_flag` is `ok`, `suspicious` or `revoked`.

### GET /api/v1/agents/{agent_id}/reputation

```json
{"agent_id": "ag_…", "score": 52, "flag": "ok", "age_days": 20,
 "reports": {"good": 1}, "reporting_sites": 1}
```

`score` is 0–100. It starts at 50, rises slowly with the agent's age, and moves with site reports. Each site's reports count once, within limits, so no single site can swing it alone. A revoked agent scores 0.

## Rate limits

A `429` means too many requests; wait and retry. Limits per agent: 20 access requests per site per 5 minutes, 10 step-up requests per minute, 60 token requests per site per minute.
