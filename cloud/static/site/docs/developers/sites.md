# Accepting agents on your site

There are two ways. Most sites want the first.

1. **Sign in with Auth Your Agent** (OpenID Connect). Add it to your login page like "Sign in with Google". No Auth Your Agent code on your site: your login library already speaks the standard. The agent gets a normal session on your site, approved by its owner on their phone.
2. **Per-request verification** (`SiteVerifier`). For APIs that agents call directly. Every request is checked, and revocation takes effect on the next request.

## Option 1: Sign in with Auth Your Agent

### What happens

1. An agent opens your login page and picks **Sign in with Auth Your Agent**.
2. Your login library sends it to Auth Your Agent, as it would to any OpenID provider.
3. The agent proves who it is with its own key. The first time it signs in to your site, its owner approves on their phone. Later sign-ins go through while that approval stands.
4. Your site receives a standard ID token and signs the agent in.

A person who clicks the button by mistake sees a page explaining that it is for AI agents. No password is ever asked for.

### Register your site

In the app: **Sites → Your websites → Register a website**. Give a name and your login library's callback address. You get:

| Setting | Value |
|---|---|
| Issuer | `https://authyouragent.com` |
| Client ID | `c_…` |
| Client secret | shown once; you can make a new one at any time |

Discovery document: `https://authyouragent.com/.well-known/openid-configuration`.

To show owners that the site is really yours, publish the verification line from the app at `https://your-site/.well-known/authyouragent-site.txt` and press **Check**. Until then the owner's approval card says the site is not verified.

### What you receive

| Claim | Meaning |
|---|---|
| `sub` | The **owner** the agent acts for. Different on every site, stable on yours. |
| `act.sub` | The **agent**. Also different on every site. Store `sub` and `act.sub` together: one owner may send several agents. |
| `act.name`, `agent_name` | The agent's name, for example `Jarvis`. |
| `name` | Display name, for example `Jarvis (agent of James)`. |
| `preferred_username`, `nickname` | A username for apps that create accounts, for example `jarvis-3f9a1c`: the agent's name plus a code that is stable on your site and unique to this agent. |
| `email` | The owner's email, only if you request the `email` scope and the owner approves sharing it. Not verified by Auth Your Agent. |
| `phone_number` | The owner's phone, with the `phone` scope and approval. Verified. |
| `amr` | `["agent", "passkey"]` when the owner approved this sign-in on their phone, `["agent", "grant"]` when an earlier approval covered it. `"password"` or `"google"` / `"microsoft"` if the owner approved another way. |
| `auth_time` | When the owner last approved. |
| `sid` | This sign-in. A sign-out notice names it (see below). |

Signing algorithm: RS256. Response type: `code`. PKCE (S256) is supported and required for public clients.

### Checking tokens from your API

The access token is a standard JWT access token ([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)), `typ` `at+jwt`, signed with the same keys as the ID token. It carries `iss`, `sub`, `aud` and `client_id` (your client ID), `exp`, `iat`, `jti`, `scope`, `auth_time`, `acr`, `amr`, `sid`, and `act` when you asked for `profile`. Any JWT library can check it offline against `/oidc/jwks`.

To find out whether a token is **still** good (the owner has not revoked, the sign-in has not ended), ask the introspection endpoint ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)) with your client ID and secret:

```bash
curl -u "$CLIENT_ID:$CLIENT_SECRET" -d "token=$ACCESS_TOKEN" https://authyouragent.com/oidc/introspect
```

You get `{"active": true, "sub": …, "act": …, "scope": …, "exp": …}`, or just `{"active": false}` once the owner revokes, the sign-in ends, or the token was issued to another site. It also accepts refresh tokens. Both endpoints are listed in `/.well-known/openid-configuration` and in `/.well-known/oauth-authorization-server` ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)), so gateways and libraries that support introspection find them automatically.

### Asking for a fresh approval

For a sign-in that should always reach the owner's phone, send `prompt=login`, or `max_age=0`. A recent approval within `max_age` seconds also counts. A fresh approval needs the owner's passkey or Google/Microsoft sign-in; a password is not enough.

`prompt=none` never shows a card: it answers `login_required` or `consent_required` when an approval would be needed.

### When the owner revokes

Revoking in the app stops new sign-ins at once. To end a session your site **already** started, use either or both of these standard mechanisms:

- **Sign-out address (recommended).** In *Your websites*, enter a sign-out address on your own domain, for example `https://your-site/auth/backchannel-logout`. When the owner revokes the agent, we POST a `logout_token` there within seconds ([OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)). Verify it against our keys (issuer, your client ID as audience, `typ` `logout+jwt`, the back-channel-logout event, no `nonce`), then end the session whose `sid` it names, and answer 200. Failed deliveries are retried for about 15 minutes. Keycloak, Authentik and many OIDC libraries support this already.
- **Refresh tokens.** Every sign-in also returns a `refresh_token`. Access tokens last 10 minutes. If your site refreshes them, the refresh fails with `invalid_grant` once the owner has revoked: end the session then. Refresh tokens rotate on every use, and reusing an old one ends that sign-in.

When your site signs the agent out itself, send its refresh token to `/oidc/revoke` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)). A sign-in lasts at most 30 days before the agent must sign in again.

### Auth.js (Next.js, Express, SvelteKit)

```js
providers: [{
  id: "authyouragent",
  name: "Auth Your Agent",
  type: "oidc",
  issuer: "https://authyouragent.com",
  clientId: process.env.AYA_CLIENT_ID,
  clientSecret: process.env.AYA_CLIENT_SECRET,
  authorization: { params: { scope: "openid profile email" } },
}]
```

Callback address: `https://your-site/api/auth/callback/authyouragent` (Next.js) or `https://your-site/auth/callback/authyouragent` (Express).

To end sessions when the owner revokes, keep the tokens in the `jwt` callback and refresh them ([Auth.js refresh-token rotation guide](https://authjs.dev/guides/refresh-token-rotation)), and add a sign-out address. Demo Shop does both in about 30 lines: [source](https://github.com/kjames2001/authyouragent/tree/main/examples/demo-shop).

### Keycloak, Authentik and other identity servers

Add an **OpenID Connect** identity provider with discovery URL `https://authyouragent.com/.well-known/openid-configuration`, the client ID and secret, client authentication "client secret sent as basic auth", and scopes `openid profile`. Use the callback address the server shows you when registering.

### WordPress and WooCommerce

Tested with WordPress 7.1, WooCommerce 11.1 and the open-source [OpenID Connect Generic Client](https://wordpress.org/plugins/daggerhart-openid-connect-generic/) plugin 3.11.3. Callback address to register: `https://your-site/wp-admin/admin-ajax.php?action=openid-connect-authorize`.

Settings, OpenID Connect Client:

- Login Type: OpenID Connect button on login form. Client ID and secret from your registration.
- OpenID Scope: `openid profile`. Agents then sign in without sharing the owner's email.
- Login Endpoint URL `https://authyouragent.com/oidc/authorize`, Userinfo `https://authyouragent.com/oidc/userinfo`, Token Validation `https://authyouragent.com/oidc/token`, JWKS `https://authyouragent.com/oidc/jwks`, Issuer `https://authyouragent.com`. Leave End Session empty.
- Identity Key: `preferred_username`. Nickname Key: `preferred_username`. Email Formatting: empty. Display Name Formatting: `{name}`.
- Turn on: Create user if does not exist, Enable Refresh Token, Redirect Back to Origin Page. Leave "Link Existing Users" off, so an agent never takes over the owner's own account.

The agent gets its own account, for example `jarvis-0be034`, shown as "Jarvis (agent of James)", with the site's default role (Customer on WooCommerce).

**WooCommerce.** The button appears on `wp-login.php`. To show it on the shop's My Account page as well, put the shortcode `[openid_connect_generic_login_button]` above `[woocommerce_my_account]` on that page.

**Revocation.** WordPress has no back-channel logout, so it relies on refresh: the session ends at the next page load after the access token expires (10 minutes at most). Plugin 3.11.3 never runs its own refresh check ([issue #675](https://github.com/oidc-wp/openid-connect-generic/issues/675), fix pending in [PR #678](https://github.com/oidc-wp/openid-connect-generic/pull/678)). Until that ships, add this file as `wp-content/mu-plugins/aya-token-refresh.php`:

```php
<?php
// Runs the OpenID Connect Generic Client token refresh that 3.11.3 never calls.
add_action( 'init', function () {
	if ( class_exists( 'OpenID_Connect_Generic' ) && OpenID_Connect_Generic::instance()->client_wrapper ) {
		OpenID_Connect_Generic::instance()->client_wrapper->ensure_tokens_still_fresh();
	}
}, 11 );
```

With it, our test shop signed the agent out at the first page load after the token expired.

### Django (django-allauth)

```python
SOCIALACCOUNT_PROVIDERS = {"openid_connect": {"APPS": [{
    "provider_id": "authyouragent", "name": "Auth Your Agent",
    "client_id": "c_...", "secret": "...",
    "settings": {"server_url": "https://authyouragent.com"},
}]}}
```

Callback address: `https://your-site/accounts/oidc/authyouragent/login/callback/`.

### Self-hosted apps

These apps already accept any OpenID Connect provider, so adding Auth Your Agent is configuration only. Each recipe below was tested end to end: an agent signed in, and the app created its account automatically. Register the app in *Your websites* first, with the callback address shown. Agents get a username like `jarvis-3f9a1c`, shown as "Jarvis (agent of James)" where the app has a display name.

Recipes use `https://your-app`; replace it with your app's address.

#### Nextcloud

Install the **OpenID Connect user backend** app (`user_oidc`), then:

```sh
occ user_oidc:provider authyouragent \
  --clientid=c_... --clientsecret=... \
  --discoveryuri=https://authyouragent.com/.well-known/openid-configuration \
  --scope="openid profile" --unique-uid=0 \
  --mapping-uid=preferred_username --mapping-display-name=name
```

Callback address: `https://your-app/apps/user_oidc/code`. The button appears on the login page. Nextcloud must be served over HTTPS, which `user_oidc` requires.

#### Forgejo and Gitea

```sh
forgejo admin auth add-oauth --name authyouragent --provider openidConnect \
  --key c_... --secret ... \
  --auto-discover-url https://authyouragent.com/.well-known/openid-configuration \
  --scopes openid --scopes profile --scopes email
```

In `app.ini`, under `[oauth2_client]`: `ENABLE_AUTO_REGISTRATION = true` and `ACCOUNT_LINKING = disabled` (Gitea: also `USERNAME = preferred_username`). Restart Forgejo afterwards, because it reads these settings only at start. Callback address: `https://your-app/user/oauth2/authyouragent/callback`.

Forgejo creates accounts automatically only when it receives an email, hence the `email` scope. The owner approves sharing it on their phone. Without it, Forgejo asks the agent to fill in a sign-up form.

#### Paperless-ngx

```sh
PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect
PAPERLESS_SOCIAL_AUTO_SIGNUP=true
PAPERLESS_SOCIALACCOUNT_ALLOW_SIGNUPS=true
PAPERLESS_SOCIALACCOUNT_PROVIDERS={"openid_connect":{"APPS":[{"provider_id":"authyouragent","name":"Auth Your Agent","client_id":"c_...","secret":"...","settings":{"server_url":"https://authyouragent.com"}}],"OAUTH_PKCE_ENABLED":true}}
```

Callback address: `https://your-app/accounts/oidc/authyouragent/login/callback/`. A new account has no permissions until an admin grants them, which is a sensible default for an agent.

#### Immich

Administration, Settings, Authentication Settings, OAuth: enable it, set Issuer URL `https://authyouragent.com/.well-known/openid-configuration`, the client ID and secret, scope `openid email profile`, button text "Sign in with Auth Your Agent", and turn on Auto Register. Callback addresses: `https://your-app/auth/login`, `https://your-app/user-settings` and `https://your-app/api/oauth/mobile-redirect`. Immich needs the email, so the owner approves sharing it on their phone.

### For agent developers

The Auth Your Agent vault adds the agent's proof to the sign-in on its own. Without the vault, the Python SDK does the sign-in in one call:

```python
redirect = agent.oidc_signin(authorize_url)   # waits for the phone when needed
session.get(redirect)                         # your HTTP session completes the sign-in
```

### Limits

- Revoking an agent stops new sign-ins, refreshes, `/oidc/userinfo` and `/oidc/introspect` at once. Sessions your site already started end only if your site uses a sign-out address or refreshes its tokens (see *When the owner revokes*). A site that does neither keeps its session until that session expires.
- Only the authorization code flow is supported.

## Option 2: Per-request verification

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
