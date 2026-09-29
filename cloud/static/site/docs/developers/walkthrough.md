# Walkthrough: Ada's errand in code

This page runs the story from [How it works](/how-it-works) on your own machine: a small job board that accepts agents, and a job-search agent that lists jobs and applies to one. You approve each step on your phone. It takes about 10 minutes.

You need Python 3.9 or newer, a phone signed in to [the app](/app) with a passkey, and this repository (the examples are in `sdk/examples/`).

## 1. Install

```sh
python -m venv .venv && . .venv/bin/activate
pip install ./sdk fastapi uvicorn
```

## 2. Start the job board

The job board is `sdk/examples/site_fastapi.py`: two jobs, `GET /api/jobs` needs the `list` scope, and `POST /api/jobs/{id}/apply` needs `apply` **and** a fresh step-up approval.

```sh
cd sdk
SITE_ID=jobs.example.com PUBLIC_URL=http://127.0.0.1:8000 \
  uvicorn examples.site_fastapi:app --port 8000
```

`SITE_ID` is the name agents ask for and the name you will see on your phone. `PUBLIC_URL` is the address agents actually call; the site checks every request's signature against it.

Leave it running and open a second terminal.

## 3. Give the agent a key

```sh
python -m authyouragent keygen --name "Job-search assistant" > key.json
```

`key.json` holds the private key. Keep it; it never leaves this machine. Copy the `jwk` value, open the app on your phone, go to **Agents → Add an agent**, name it "Job-search assistant" and paste the key. The app shows the agent id (`ag_…`).

## 4. Run the errand

```sh
cd sdk
AGENT_ID=ag_… KEY_FILE=key.json SITE_URL=http://127.0.0.1:8000 \
  SITE_ID=jobs.example.com python examples/agent.py
```

What happens, step by step:

1. **The agent asks.** It prints `Asking for access; approve it on your phone…` and waits.
2. **Your phone shows the request:** Job-search assistant wants access to jobs.example.com, to list and apply. Approve it. (Try **Limit this access** first: end after 1 day, 3 sensitive actions.)
3. **The agent lists jobs.** The site verifies the pass and answers: `Jobs: {'j1': 'Lighthouse keeper', 'j2': 'Bridge inspector'}`.
4. **The agent applies.** The site answers `403 stepup_required`, because applying is sensitive. Your phone asks again: *apply*. Approve it with your fingerprint (a password can't approve this).
5. **The site accepts:** `200 {'applied': True, 'job': 'Lighthouse keeper'}`.

Run it a second time: the agent already has access, so step 2 is skipped, but step 4 asks again, as it should for every application.

## 5. Take it back

In the app, open **Sites** and tap **Revoke** on jobs.example.com. Run the agent again. This time the service answers with an error carrying a `next_step` for the agent (see [For AI agents](/docs/agents)), and the agent has to ask you again.

Open **Activity**: every request, approval, step-up and the revoke are listed.

## What each side did

- **The agent** used two calls from the SDK: `ensure_grant(site, scopes)` and `request(method, url, stepup_action=...)`. The SDK handled the tokens, the per-request DPoP proofs and the step-up.
- **The site** used one: `verifier.verify(request)`, which returns the agent, the person it acts for, the scopes, and whether a step-up is attached.
- **You** approved twice and revoked once, from your phone.

## Next

- Put your own site behind it: [Accepting agents on your site](/docs/developers/sites)
- Build a real agent: [Building an agent](/docs/developers/agents), or the [JavaScript SDK](/docs/developers/quickstart)
- Give agents your API as tools: [MCP tools for your site](/docs/developers/mcp)
