# Running agents for your users (operator accounts)

If your company runs AI agents for many people, an operator account lets you create an agent for each user once they agree. Every agent gets its own key and its own Web Bot Auth address, approvals still go to that user's phone, and the user can stop your agents with one tap.

Operator accounts are in a free pilot. To join, write to [support@authyouragent.com](mailto:support@authyouragent.com); we switch each company on by hand.

## What you can and cannot do

You can:

- Send a user to our consent page once. After they confirm with their passkey, create agents in their name.
- See your own connections and your agents' status: active, removed, blocked or suspended.
- Delete your agents, or end a connection, for example when the user closes their account with you.

You cannot:

- Approve anything. Payments, posts, sign-ins, site access and take-overs go only to the user's phone. No operator credential works on an approval.
- See the user's email, phone number, other agents, approvals or activity. You get a connection id and a `sub` that is unique to your company.
- Use the user's password manager in a browser you run, unless the user turns that on for the agent.

## 1. Register

Sign in to the app, then register your company. Use the address users will return to after they connect:

```
POST /api/operators
{"name": "Example Co", "redirect_uris": ["https://app.example.com/aya/callback"], "browser": "operator"}
```

Set `browser` to say where your agents' browser (the vault) runs:

- `operator`: on your computers.
- `user`: on the user's own machine, through a [remote vault](/docs/developers/takeover).

The consent page tells the user which one it is.

The response includes your **secret**. It is shown once, so store it like a password. It also includes a verification line. Publish that line at `https://<your site>/.well-known/authyouragent-site.txt`, then call `POST /api/operators/{id}/verify`. We switch your account on after that.

Your API calls use HTTP Basic auth, with your operator id as the username and the secret as the password.

## 2. Connect a user

Send the user's browser to:

```
https://authyouragent.com/connect?operator=op_...&redirect_uri=https://app.example.com/aya/callback&state=...&code_challenge=...&code_challenge_method=S256
```

PKCE (S256) is required. The page explains, in our words, that your agents can never approve anything and that the user can disconnect at any time. The user confirms with their passkey; a password is not enough. If they don't have an account yet, the page points them to create one.

We redirect back with `code`, `state` and `iss`, or with `error=access_denied` if they said no. Exchange the code within 60 seconds:

```
POST /api/v1/operator/token          (HTTP Basic)
{"code": "...", "code_verifier": "...", "redirect_uri": "https://app.example.com/aya/callback"}

-> {"connection_id": "cn_...", "sub": "...", "max_agents": 5}
```

## 3. Create agents

Generate a P-256 key pair where the agent runs, and send only the public key:

```
POST /api/v1/operator/agents         (HTTP Basic)
{"connection_id": "cn_...", "name": "Shopper", "jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}}

-> {"agent_id": "ag_...", "name": "Shopper (via Example Co)", "browser": "operator"}
```

The user's phone gets a note saying that you added an agent. A user allows 5 agents from you by default and can change that.

From then on the agent works like any other: the [Python and JavaScript SDKs](/docs/developers/agents), the MCP server, the vault, site sign-in and Web Bot Auth. Give the vault the agent id and its private key.

## 4. Status and stopping

```
GET    /api/v1/operator/connections
GET    /api/v1/operator/agents[?connection_id=cn_...]
DELETE /api/v1/operator/agents/{agent_id}
DELETE /api/v1/operator/connections/{connection_id}
```

When the user removes an agent or disconnects you, or you delete one, everything about that agent stops:

- its site access is revoked;
- its open requests are cancelled;
- its key list becomes empty;
- sites that signed it in are told through back-channel logout.

A connection that has ended stays ended. The user can connect again, which creates a new connection.

## The password manager, when you run the browser

If the agent's browser runs on your computers, you control the machine the owner's sign-ins would be filled on. So for those agents, `list_secrets`, `fill_secret` and `save_secret` are refused until the user turns the password manager on for that agent in the app. Vault 0.3.40 and later enforce this. Until then, use `request_takeover`: the user signs in from their phone, and your agent never sees the password.
