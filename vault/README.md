# Auth Your Agent vault

The vault is the browser your agent uses. It runs in a container on your
machine. The agent drives it only through the vault's API (open a page, click,
type, read), so it never gets the browser's cookies. When a site asks for a
password, a code or an approval, you take over from your phone, and the agent
is disconnected while you are in control.

## Start it

You need Docker and Python 3.9+.

```bash
pip install "authyouragent[mcp]"
authyouragent vault up --agent-id ag_... --key ./agent.pem
```

`vault up` pulls the image, creates a token, and starts the vault on
`127.0.0.1:7801` with every setting below. It prints the `env` block for your
MCP client:

```json
{"mcpServers": {"authyouragent": {
  "command": "authyouragent-mcp",
  "env": {"AYA_AGENT_ID": "ag_...", "AYA_KEY_FILE": "/path/agent.pem",
          "AYA_VAULT_URL": "http://127.0.0.1:7801",
          "AYA_VAULT_TOKEN_FILE": "~/.authyouragent/vault/token"}}}}
```

Other commands:

```bash
authyouragent vault status   # running? gVisor? session active?
authyouragent vault down     # signs out of every site, then stops
authyouragent vault env      # print the env block again
```

## What protects what

| Layer | What it stops |
|---|---|
| Separate browser process, API only | The agent cannot read cookies or the browser's memory. The debug port exists only inside the container. |
| Take over | Passwords, one-time codes and sign-in approvals are typed by you, on your phone. The agent's connection is closed while you are in control, and the phone viewer can only send taps and plain text (no keyboard shortcuts). |
| Step-up approval | Before a click (or Enter) that submits a form, or on a button that says create, send, save, delete, pay, publish and similar, the vault asks you on your phone and waits. The request shows the button's words. The agent cannot skip it: every click goes through the vault. Search boxes and sign-in steps (password, code, "Verify") are not interrupted; "Authorize" and "Allow" on a sign-in page still ask. Add your own words with `VAULT_APPROVE_WORDS=transfer,wire`. |
| Egress filter | The browser reaches only the public internet. Loopback, private networks, link-local (cloud metadata), CGNAT and the vault's own ports are refused. Checked on the resolved address, so DNS tricks do not help. |
| Browser policy | No internal pages (`chrome://settings`, downloads...), no `file://`, no extensions, no downloads, no saved passwords or autofill. |
| Chromium sandbox | Always on. Each page runs in its own restricted process. `vault up` supplies the seccomp profile this needs; no extra privileges are granted and all capabilities are dropped. |
| gVisor (optional, Linux) | If Docker has the `runsc` runtime, `vault up` uses it automatically: the whole vault then runs on gVisor's own kernel instead of your host's. Install: https://gvisor.dev/docs/user_guide/install/ |
| In-memory profile | The browser profile lives in memory and is destroyed at the end of every session. |
| Sign-out first | At the end of a session the vault signs out of every site it can, checks it worked where possible, then destroys the profile. It ends the session by itself if the agent stops sending heartbeats or you revoke the agent. |

## Known limits

- **Who can read the session.** Anyone with root or Docker access on the
  machine running the vault can read the browser's memory. Run the vault where
  the agent has neither: a separate VM, LXC or machine, reached over the network.
  If the agent runs as root on the same host, the vault still stops casual
  cookie theft by the agent's tools, but not a determined root process.
- **Hard kills.** If the vault is killed before it can sign out, the cookies
  are gone with the in-memory profile, but the sessions stay valid on the
  sites' side until they expire. The vault keeps a list of site names (never
  cookies) in `~/.authyouragent/vault/state`; on the next start it tells you,
  on your dashboard, which sites were left signed in and where to end those
  sessions.
- **Sign-out on unknown sites.** Known routes (Google, GitHub, Glama) are
  checked. Elsewhere the vault tries, in order: a route that worked before, the
  site's published OpenID Connect sign-out endpoint, then a "Sign out" link or
  button on its pages, and confirms by the session cookie being cleared. When
  none works it reports "wiped locally, not signed out".
- **Step-up approval reads the page.** Every form submit asks, but a button
  outside a form that sends its request from a script, with a label that does
  not say what it does (an icon, "OK"), can pass without approval. Add words
  with `VAULT_APPROVE_WORDS`, and keep the agent's grants narrow.
- **One session per vault.** Run one vault per owner session.
- **Cookie binding.** Chrome's Device Bound Session Credentials (DBSC) will make
  stolen cookies useless on other machines, but it needs a TPM and is Windows-only
  so far. The vault will use it once Linux Chromium supports it.

## Settings

| Variable | Default | |
|---|---|---|
| `VAULT_SIZE` | `412x860` | page size in CSS px (phone-shaped, for take over) |
| `VAULT_SCALE` | `2` | device pixel ratio |
| `VAULT_LEASE_S` | `90` | end the session if the agent is silent this long |
| `VAULT_APPROVE_WORDS` | | extra words that need your approval |
| `AYA_VAULT_IMAGE` | `ghcr.io/kjames2001/authyouragent-vault:latest` | image `vault up` runs |

Run it by hand (what `vault up` does):

```bash
docker run -d --name authyouragent-vault --shm-size=1g --stop-timeout 120 \
  --security-opt seccomp=vault/seccomp.json --security-opt no-new-privileges --cap-drop ALL \
  [--runtime runsc] \
  -e VAULT_TOKEN=... -e AYA_AGENT_ID=ag_... -e AYA_CLOUD=https://authyouragent.com \
  -v /path/agent.pem:/run/secrets/agent.pem:ro -v /path/state:/var/lib/vault \
  -p 127.0.0.1:7801:7801 ghcr.io/kjames2001/authyouragent-vault:latest
```

Build from source: `docker build -f vault/Dockerfile -t authyouragent/vault .`
