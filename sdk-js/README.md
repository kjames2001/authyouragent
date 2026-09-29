# authyouragent (JavaScript / TypeScript)

SDK for [Auth Your Agent](https://authyouragent.com): let AI agents act for a person on websites, with the person's approval on their phone.

- **Agents** ask a person for access, then call sites with a short-lived pass and a fresh DPoP proof (RFC 9449) on every request.
- **Sites** check each call in one line.

No dependencies. Uses the Web Crypto API and `fetch`: Node.js 18+, Deno, Bun, Cloudflare Workers and other edge runtimes.

Full documentation: https://authyouragent.com/docs/developers/quickstart

## Install

Not on npm yet. From the source tree:

```
npm install ./sdk-js
```

## Agent

```js
import { AgentClient, keygen } from "authyouragent";

// once: create the agent's key, register `jwk` in the app (Agents → Add an agent)
const key = await keygen();

const agent = new AgentClient({ agentId: "ag_…", privateKeyPem: key.privateKeyPem });

await agent.ensureGrant("jobs.example.com", ["list", "apply"]);   // the person approves on their phone
const res = await agent.fetch("https://jobs.example.com/api/jobs");

// sensitive action: asks the phone again if the site says so
await agent.fetch("https://jobs.example.com/api/jobs/j1/apply", { method: "POST", stepupAction: "apply" });
// reaching the site at another address (proxy, local test)? name the site id:
await agent.fetch("http://127.0.0.1:8000/api/jobs", { site: "jobs.example.com" });
```

`ensureGrant` throws `AgentError` with `code` `"denied"`, `"expired"`, `"timeout"` or `"revoked"`.

## Site

```js
import { SiteVerifier, AuthError } from "authyouragent";

const verifier = new SiteVerifier({ expectedAudience: "jobs.example.com",
                                    publicBaseUrl: "https://jobs.example.com" });

// Cloudflare Worker / Next.js route / Deno / Bun
export default {
  async fetch(request) {
    try {
      const a = await verifier.verify(request);
      if (!a.scopes.includes("list")) return Response.json({ error: "insufficient_scope" }, { status: 403 });
      return Response.json({ jobs: [], forUser: a.userId });
    } catch (e) {
      if (e instanceof AuthError) return Response.json({ error: e.error }, { status: 401 });
      throw e;
    }
  },
};
```

Express works the same way (`verifier.verify(req)`); set `publicBaseUrl` so the verifier knows the public URL agents signed.

For sensitive actions, pass the action name and check `stepup`:

```js
const a = await verifier.verify(request, { action: "apply" });
if (!a.stepup) return Response.json({ error: "stepup_required" }, { status: 403 });
```

`mode: "local"` checks passes without a network call per request, using cached signing keys and a signed revocation list (refreshed every `revTtl` seconds, default 60).

## Tests

```
CLOUD=https://… PHONE_HELPER=$PWD/test/phone_helper.py npm test
```

The live test runs a real agent and a real site against a running Auth Your Agent service, in both cloud and local mode, with a software passkey standing in for the phone.

## Licence

MIT
