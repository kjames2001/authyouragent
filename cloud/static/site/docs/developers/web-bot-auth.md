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
- The agent's owner has not revoked it. When they do, the agent's key list becomes empty. Verifiers keep a list for at most five minutes (`Cache-Control: max-age=300`), after which the signature stops verifying everywhere.

It does not tell you who the owner is. Agent addresses are random and carry no personal information. If you need to know the person behind the agent, use [Sign in with Auth Your Agent](/docs/developers/sites).

## Checking signatures

Any Web Bot Auth verifier works. The verifier reads `Signature-Agent`, fetches the key list from that address and checks the signature. Trust the agent addresses under `agents.authyouragent.com` to accept only Auth Your Agent agents.

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

Cache each key list for no longer than its `Cache-Control` allows (five minutes). A list that fails to load says nothing about the agent: treat the request as unverified rather than as revoked.

## Sites behind Cloudflare

Cloudflare verifies Web Bot Auth for agents it has registered one by one. Auth Your Agent gives each agent its own key, which Cloudflare's registration does not support yet. Until it does, Cloudflare passes the headers through to your site unverified, and you can check them yourself as above.

## For agent owners

Signing is on by default from vault 0.3.16. The key is created on first start and kept in the vault's state folder. To send requests unsigned, start the vault with `VAULT_WEB_BOT_AUTH=off`.
