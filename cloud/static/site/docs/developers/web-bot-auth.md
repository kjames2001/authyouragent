# Recognising agents: Web Bot Auth

Every request an Auth Your Agent vault sends carries a signature under [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/), the IETF draft that Cloudflare, Google and others are standardising. Your site can check it and know for certain that a request came from one particular agent, and that its owner has not revoked it.

It complements [Sign in with Auth Your Agent](/docs/developers/sites). Sign-in gives the agent an account on your site. Web Bot Auth identifies the agent on every request, including pages it reads without signing in.

## What a signed request looks like

```
GET /products/42 HTTP/1.1
Host: shop.example
Signature-Agent: "https://a-3f9a1c2b7d10.agents.authyouragent.com"
Signature-Input: sig1=("@authority" "@method" "@path" "signature-agent");created=1790980000;keyid="poqk...";alg="ed25519";expires=1790980300;nonce="...";tag="web-bot-auth"
Signature: sig1=:...:
```

- `Signature-Agent` names the agent. Each agent has its own address, and the address stays the same when its key changes. Log it, rate-limit it, allow it or block it, as you would an IP address.
- The signature covers the host, method and path, and is valid for five minutes, so a copied one cannot be reused on another page.
- The key list is at that address, under `/.well-known/http-message-signatures-directory`. It is a standard JWK set with the agent's own proof attached.

## What a valid signature tells you

- The request came from the vault holding that agent's key. Each vault makes its own key, and the private half never leaves the owner's machine. Auth Your Agent publishes only the public half and never sees the requests.
- The agent's owner has not revoked it. When they do, the agent's key list becomes empty. A verifier that fetches the list from the agent's address keeps it for at most five minutes (`Cache-Control: max-age=300`), after which the signature stops verifying. A copy of the list that reached you some other way, such as a shared key list, carries the agent's own proof, which is valid for one hour, so a revoke reaches it within the hour.

It does not tell you who the owner is. Agent addresses are random and carry no personal information. If you need to know the person behind the agent, use [Sign in with Auth Your Agent](/docs/developers/sites).

## Checking signatures

Any Web Bot Auth verifier works. The verifier reads `Signature-Agent`, fetches the key list from that address and checks the signature. Trust the agent addresses under `agents.authyouragent.com` to accept only Auth Your Agent agents.

- **Python:** `webbotauth.verify` in our SDK (`pip install authyouragent`, version 0.3.39 or later). It checks any agent's signature, not only ours. See below.
- **Node.js, Cloudflare Workers:** Cloudflare's [`web-bot-auth`](https://www.npmjs.com/package/web-bot-auth) package. Our own tests verify vault requests with it.
- **Caddy:** Cloudflare's [Caddy plugin](https://github.com/cloudflare/web-bot-auth/tree/main/examples/caddy-plugin).
- **Apache:** [web-bot-auth-apache](https://github.com/garyillyes/web-bot-auth-apache).

A minimal Node.js check:

```js
import { verify, parseSignatureAgentHeader } from "web-bot-auth";
import { verifierFromJWK } from "web-bot-auth/crypto";

const agent = parseSignatureAgentHeader(request.headers.get("signature-agent")).entries[0].uri;
if (!new URL(agent).hostname.endsWith(".agents.authyouragent.com")) throw new Error("not an Auth Your Agent agent");
const dir = await (await fetch(agent + "/.well-known/http-message-signatures-directory")).json();
await verify(request, {
  resolver: async (c) => verifierFromJWK(dir.keys.find((k) => k.kid === c.keyid)),
});
// verified: `agent` is the agent's stable address
```

### Python

```python
from authyouragent import webbotauth

result = webbotauth.verify(request)       # Starlette/FastAPI, Flask or Django request
if result.verified:
    agent = result.agent                  # the address its keys came from
```

`result.outcome` is one of four values:

- `verified`: the signature checks out against a key the agent's address publishes. `result.agent` is that address (its key-list URL). Log, rate-limit, allow or block by it.
- `invalid`: the signature is wrong, expired, made for another page or method, or made with a published test key.
- `unverified`: there was not enough to decide. For example, the key list could not be fetched or does not hold the key. This says nothing bad about the agent, so treat the request as you would an unsigned one.
- `unsigned`: the request has no Web Bot Auth signature.

`result.reason` says why in plain words. To accept only Auth Your Agent agents, also check that `result.agent` is under `https://` and `.agents.authyouragent.com/`.

The first request from a new agent fetches its key list over the network. In async code, call `await asyncio.to_thread(webbotauth.verify, request)`. Without a framework, pass the parts instead: `webbotauth.verify(method="GET", url="https://shop.example/p/1?x=2", headers=headers)`. Use the URL as the client sent it.

What it does for you:

- **Any agent:** it follows the draft's rules for every address, not only ours. It accepts Ed25519, RSA-PSS and ECDSA keys, a `directory` or `jwks_uri` key list, and both header forms (`sig1="https://…"` and the older plain string).
- **Agent addresses:** it pairs each key with the address it was fetched from. A request that uses one agent's key but names another agent's address is not attributed to either.
- **Fetching key lists safely:** each key list is fetched over HTTPS from a public address only, never from your internal network. Fetches give up after 5 seconds and 64 kB, and redirects are not followed.
- **Caching:** key lists are cached as their `Cache-Control` says, and at least 60 seconds. If an agent's key list fails to load, the last good copy is used for up to a day and the result is marked `stale`.
- **Refused signatures:** shared secrets (`hmac-sha256`), the published RFC 9421 example keys, and signatures valid for more than 24 hours are refused.

To change these limits, create your own `webbotauth.Verifier(...)` and call its `verify` method. One verifier per process is enough.

Fetch each key list from the agent's address yourself, and cache it for no longer than its `Cache-Control` allows (five minutes). That is what makes a revoke reach you within five minutes. A list that fails to load says nothing about the agent: treat the request as unverified rather than as revoked.

## Sites behind Cloudflare

Cloudflare verifies Web Bot Auth for agents it has registered one by one. Auth Your Agent gives each agent its own key, which Cloudflare's registration does not support yet. Until it does, Cloudflare passes the headers through to your site unverified, and you can check them yourself as above.

## For agent owners

Signing is on by default from vault 0.3.16. The key is created on first start and kept in the vault's state folder. To send requests unsigned, start the vault with `VAULT_WEB_BOT_AUTH=off`.
