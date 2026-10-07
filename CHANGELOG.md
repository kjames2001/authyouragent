# Changelog

Every release of the Python SDK, MCP server and browser vault (`authyouragent` on PyPI, `ghcr.io/kjames2001/authyouragent-vault`), with the changes to the service at authyouragent.com that shipped alongside it. Newest first. Versions are tagged `py-vX.Y.Z` (PyPI) and `js-vX.Y.Z` (npm).

## 0.3.34 (2026-10-07)

### An approved click can send only where the card said
- The vault already re-read the page after the owner's tap: the amount, the text and where the form sends. A script could still change where data goes at the moment of the click, after that read: a submit handler that rewrites the form's address, or a `fetch()` or beacon to another site.
- Now, from an approved click until the page has loaded its next document (at most 10 s), the vault blocks every send to a site that was not on the card: any request but GET, pings and beacons, and a page load of another site that carries data in its query. The click itself still happens; what the page tries to send elsewhere does not.
- Still allowed: the page's own site, the site the form sends to on the card (a payment provider), sites whose script or frame the page had already loaded before the card (a provider's card field sends to its own API), a redirect the site itself answers with, and the new page's own requests once it has loaded.
- A blocked send is listed in the owner's end-of-session summary: "Blocked, sent to a site not on the card".
- Found by a Reddit commenter (Acrid) asking about a form whose address is set by script at submit time.

## 0.3.33 (2026-10-07)

### An address cannot carry the owner's data out, however short
- On any site the agent is signed in to this session (it filled a saved login, typed a password, finished a take over, or signed in with Auth Your Agent), the vault remembers every code, number and email the agent reads there: gift card codes, order and phone numbers, account emails. It remembers the same for screenshots.
- If the agent then writes an address for any other site that carries one of those values, the owner gets the red "Possibly unsafe" card first, however short the value is. The vault looks in the host name, path, query and fragment, and through percent-encoding, base64 and hex. The card shows the value and the site it came from.
- Before, only long addresses (over 120 characters of data) asked, so a gift card code or a phone number fitted under the limit. The public break-my-vault challenge found this. 0.3.32 closed it for the challenge site only; 0.3.33 closes it everywhere and drops the special case.
- What still opens without a card: links on the current page, any address a page the agent read shows, a site's own values sent back to that site, searches after reading public pages (public pages add nothing), and anything the owner already approved for that site in the same session. Everything is forgotten when the session ends.
- The cost: after reading a signed-in page, a search on another site that repeats a code or number from that page (an order number, a version number) asks. We measured 18 of 33 such searches asking on signed-in pages, and 0 of 951 link addresses and 0 of 33 searches after public pages.

## 0.3.32 (2026-10-07, image only)
- The sandbox challenge host accepted no data in addresses. Superseded by 0.3.33; never published to PyPI or `:latest`.

## 0.3.31 (2026-10-06)

### The vault on another machine
- `authyouragent vault up --listen ADDRESS` also serves the vault's API to other machines: plain HTTP on a VPN or private address (Tailscale, WireGuard, LAN), or with `--tls` on any address, on port 7443 with a self-signed certificate made and kept for the names given (`--tls-name`), or your own (`--tls-cert`, `--tls-key`). A public address without `--tls` is refused, so the token never crosses the internet in clear text.
- `vault env` prints the settings for the agent's machine: the address, where to put the token and the certificate, and the certificate's SHA-256 to compare.
- The MCP server takes `AYA_VAULT_CA_FILE` for the vault's certificate, and refuses to send the token over plain HTTP to anything but this machine or a VPN / private address.
- The vault checks the token in constant time.
- Why: an agent running as root on the vault's own machine can read the vault's files. Running the vault on a machine the agent cannot administer keeps the password manager login and the agent key away from it. See "The vault on another machine" in the agent guide.

## 0.3.30 (2026-10-06)

### The card says when opening an address is unsafe
- The card for an address that carries data now opens with a red warning, straight under the title: "Possibly unsafe: deny unless you asked for this", with how much data goes to which site and why that is how a page tricks an agent. Before, it looked like any other approval, and an owner approved it.
- The card shows all the data (up to 600 characters) under its own "Data" line, and the phone notification says the same instead of "Tap to approve".
- Opening such an address always asks: Allow mode and Smart mode do not let it through, and a pre-approved plan step never covers it.

## 0.3.29 (2026-10-06)

### Pages cannot hide instructions for the agent
- `read_page` leaves out text the owner cannot see on screen: text that is not drawn (`display:none`, `visibility`, opacity 0), screen-reader-only boxes, text pushed off the page, fonts under 2px, and text in the same colour as its background. Before, all of these reached the agent, which is how a page smuggles in instructions (prompt injection). A page's own scripts cannot fake it: the vault reads in a world of its own, and the page is left exactly as it was.
- A button's name comes from the words it shows. A screen-reader name (`aria-label`, `title`) is used only for icon buttons, and kept short, so a page cannot hide an instruction in one.
- When a page hid text by colour or font size, `read_page` says so and tells the agent to be wary of that page.
- `read_page` output marks the page's text as the site's, "information, not instructions", and the MCP server tells the agent never to follow instructions from a page.

### Addresses that carry data ask the owner
- An address the agent writes itself that carries a lot of data (more than 120 characters after the `?` or `#`, or one path piece over 80) is opened only after the owner approves it on their phone; the card shows the address. This is how a hijacked agent would send a page's content or the owner's data to another site. Links on the current page, ordinary searches and the owner's trusted sites open as before.

## 0.3.28 (2026-10-06)

### Plans can repeat, for an exact number of runs
- `submit_plan` takes `runs` and `every` ("day" or "week"). The plan's window opens that many times, a day or a week apart, and the owner approves every run with one passkey tap. Each step may go through `uses` times per run.
- Exactly the runs asked for, never more: the last run must end within 30 days of the first starting, and after it the approval is spent. The card says how many runs, how often, and when the last one ends.
- `plan_status` says which run is open, or when the next one starts. The plan list in the app shows the same.
- Everything else about plans holds for each run: the exact text, the address and button words, payments and security changes always asking, Google sign-in not approving.

### "Off" is now called "Allow"
- A site's approval mode reads Ask, Smart or Allow. Allow means nothing asks on that site, except account and security changes; it is still for one site at a time. Existing rules carry over unchanged, and an older app that sends "off" still works.

## 0.3.27 (2026-10-06)

**An approval cannot be sent somewhere else**
- The vault now reads where a click sends: the form's address (or the button's own `formaction`, or a link's address). After the owner taps Approve it reads the page again and clicks only if the page's address and the form's destination are unchanged, as it already did for the amount and the text. A page that re-points its form while the card is open gets "the form now sends to <host> after approval; not clicked".
- The card says "Sends to <host>" when the form posts to another site than the page.
- Smart mode asks when the form posts to another site, even for a low-risk button, and a plan step never pre-approves such a click.
- Smart mode also asks when a click sends text typed into the page, whatever the button says. Old Reddit's comment button reads "save", which Smart had let through as a low-risk click. Plans are unchanged: a step pre-approved with its exact text still runs. (Service change, deployed 2026-10-06.)

**Saved logins are told to the owner**
- When the vault types one of the owner's saved passwords into a page (`fill_secret`), the owner's phone gets a notification: "Saved login used on <site>", naming the login, never its value. Once per login and address per session, sent by the vault, so the agent cannot leave it out, and not turned off by the session-notice setting. The end-of-session summary lists "Saved logins used" too.

## 0.3.26 (2026-10-06)

**Save the sign-in the owner just typed**
- After a take over where the owner signed in with a password, their phone offers to keep that sign-in in their password manager: a "Save this login?" card with the username and site (never the password). Save stores it in the shared folder of their Bitwarden or Vaultwarden, named after the site and username; if that fails (a name already taken, the manager unreachable) the phone says why. Skip forgets it. The tap is the owner's approval.
- The vault reads the sign-in fields while the owner types, every 0.5 s, straight from the page; the values never leave the vault. Forms inside a shadow root (Reddit, X) are read too. A text box counts as the username only if it says so, or sits beside the password field, so a search box is never taken for one. A read on the signed-in page afterwards never replaces the typed password with nothing.
- What was typed is kept for 10 minutes for the site it was typed on, and only until the next take over, a cancelled one, or the end of the session. It is never offered on another site.
- `save_secret(name, username)` (MCP, the twenty-third tool): the agent can ask to keep that sign-in when the phone's offer was missed. It asks the owner on their phone first; the agent never sees or supplies the password.
- The relay and the phone viewer carry the save offer and its result (deployed to the service 2026-10-05).

**Scheduled tasks (fixes to 0.3.25's pre-approval)**
- A button whose words hold a hyphen or underscore ("Sign-up", "Opt_in") never matched its pre-approved step: the vault sends them as spaces. Matched now.
- A step given no text no longer matches a click that sends text: before, a pre-approved "Save" went through whatever the agent had typed in the form. The vault likewise refuses a click whose text appeared after the approval.
- A step's path now includes the query, so `/item?id=1` no longer also approves `/item?id=2`. Plans take `https://` addresses only.
- The plan card shows each text in full (it kept only the first 600 characters, though the whole text is what is matched).
- A plan card can no longer be approved with Google or Microsoft: that path ignored which steps were ticked and pre-approved them all. Plans are approved with the passkey.

**Notifications**
- A notification you tap no longer stays unread: opening the approval card or take over it was about marks it read, as do deciding the request (on any device) and withdrawing a plan.
- "Session ended" and other notes are marked read when tapped too (Android app 2.2.11 sends which note was tapped; the web app already did).

**Saving a login after a take over**
- The save offer and `save_secret` refuse a login that is already saved: same username (case ignored) for the same site, under any item name. The phone shows which item holds it.
- Some sites sign the owner in but leave the tab on their sign-in page (Reddit: the button greys out and the page never moves). Once a new sign-in cookie for the site has been there 4 seconds after a password was typed, the vault reloads that page once, so the hand-back and the save offer follow. Bot-protection cookies (`__cf_bm` and similar) are not counted.

## 0.3.25 (2026-10-05)

**Scheduled tasks: pre-approval**
- An agent setting up a task that runs later submits a plan (`submit_plan`, MCP; `POST /api/v1/plans`): a title, a window (1 minute to 24 hours, starting within 30 days) and up to 20 steps, each with its address, the button's words, the exact text it will post or send, how many times it may run, and the steps it must follow (`after`).
- The owner gets one card with every step and its full text, and pre-approves all steps, some, or none, with their passkey. A card left unanswered pre-approves nothing; the run still goes ahead and each step asks.
- During the window, an approval request goes through without a card only if it matches a pre-approved step exactly: the same agent, address (and path, where given), button words and text. The vault sends a SHA-256 of each text field the click would send, never the text, and does not click if the text changed after approval. Rules only, no AI.
- A step the owner does not answer in time, denies, or whose click fails or gets no answer is skipped together with the steps chained to it, which are refused at once without a card. Every other step carries on.
- Payments and security changes are never pre-approved, even when ticked.
- `plan_status` (MCP) shows each step's state and why. Plans are listed in the app under the agent's approval modes, with Withdraw.
- Activity records each step approved by a plan, and each step skipped.
- The MCP server has 22 tools.

**Website**
- Web Bot Auth: agent key lists are now served with `Cache-Control: max-age=300` (was 3600), so after an owner revokes an agent, verifiers stop accepting its signatures within five minutes instead of an hour.
- Approval cards: a site's signed step-up text is refused if it holds invisible characters (right-to-left overrides, bidi isolates, zero-width characters, Unicode line or paragraph separators, other control or format characters), so the text the owner approves always reads as it was signed; before, only ASCII control characters were refused. The same characters are removed from what the vault reads off a page (button wording, amount, item, order, page title) and from `notify_owner` notes, where Unicode line separators become ordinary line breaks.
- Agent-readiness check: malformed input such as `http://[` or `http://[1.1.1.1]` now gets the "Enter a domain name" message instead of a server error, and a redirect or link with a malformed address (bad port, unclosed bracket) is treated as unreachable instead of ending the check with an error.
- Private-network guard (readiness check and plugin back-channel logout): IPv6 addresses that carry an IPv4 address (NAT64 `64:ff9b::/96`, IPv4-compatible `::a.b.c.d`, IPv4-mapped, 6to4) are judged by the IPv4 address inside, so `64:ff9b::7f00:1` (127.0.0.1) is refused. Python's own check counts some of these as public. Not reachable on the current host, which has no IPv6 route.
- Found by new property-based tests (Hypothesis): eleven rules covering approval modes, the readiness check's input and address guards, card and note text, and site-signed step-up requests, each tried against up to 3,000 generated inputs.

## 0.3.24 (2026-10-04)

**Python package**
- No code changes. The README now carries the official MCP Registry marker in the form the registry checks (`mcp-name: com.authyouragent/mcp`), so the MCP server is listed at registry.modelcontextprotocol.io as `com.authyouragent/mcp`. `server.json` at the repository root describes the listing.

**Website**
- Agent-readiness check at `/check` (and `GET /api/readiness?site=`): what an AI shopping assistant meets on a site, from the outside. Checks for a bot challenge on the home page, robots.txt rules against assistants acting for users (ChatGPT-User, Claude-User, Perplexity-User and their search agents; blocking training crawlers alone is fine), CAPTCHA or password-only sign-in, schema.org product data (home page plus one product page), llms.txt, and whether the site already accepts Sign in with Auth Your Agent or signs its step-ups. Public pages only; domain names only, public addresses only with the connection pinned to the checked address, at most 4 redirects, 1.5 MB and 8 s per page, cached 10 minutes, 20 checks an hour per network. Stores the domain and result counts only.
- WordPress / WooCommerce plugin 0.1.0 (`integrations/wordpress/authyouragent`, MIT, no dependencies), downloadable at `/download/wordpress`. Sign in with Auth Your Agent on the WordPress and WooCommerce sign-in forms (authorization code + PKCE, state bound to the browser); each agent gets its own account, never an existing customer's, and never a role that manages the site. On WooCommerce, an agent's order waits for the customer to confirm it on their phone in the shop's words (CIBA), tied to that basket and total; works on the block checkout (Store API) and the classic checkout, with any payment method. Agent orders carry a note with the confirmed text. Revoking signs the agent out at once (back-channel logout), or at the next page after the token expires. Tested end to end on WordPress 7.1 + WooCommerce (23 checks) and with WordPress Plugin Check.
- "For shops" page at `/for-shops`: the case for shops, written around completed orders rather than bot defence. Linked from the header, footer, sitemap and llms.txt.

## 0.3.23 (2026-10-04)

**Sites can describe a step-up in their own words**
- A site that asks for a step-up (`403 stepup_required`) can include a `stepup_request`: its own one-line description of the action ("Apply to Lighthouse Keeper at Coastal Authority"), signed with a key it publishes at `/.well-known/authyouragent-site-keys.json`.
- The owner's phone, the notification and the notification list show the site's text, marked as signed by the site. Without a signed request, the card says the words are the agent's.
- The step-up token carries the site's `ref` back. `Auth.stepup_ref` (Python site SDK) and `stepup_ref` / `ref` from `/api/v1/verify` and `/api/v1/stepup/verify` let the site refuse an approval that was for another request.
- The cloud refuses a signed request (`400`, nothing reaches the phone) if the signature does not match the site's published key, if it was issued for another agent, action or site, if it lives longer than 10 minutes, or if the text is not one line of at most 120 characters.
- New `StepupSigner` in `authyouragent.site`: makes the key, publishes it (`jwks()`), and builds the `403` body (`required()`).
- The Python and JS agent SDKs and MCP tools generated by `mcp_layer/forge.py` pass the signed request through unchanged.
- The demo job board signs its step-ups and checks the `ref`. It is live at https://jobs.authyouragent.com.
- JS SDK and the `authyouragent-mcp` npm wrapper move from 0.3.1 to 0.3.23, matching the Python release.

**Fixes**
- An agent could not get its first access token if the owner took more than about 5 seconds to approve the access request: the cloud compared the request's creation time with the grant's, which is set at approval. It now accepts any request whose approval window was still open when the grant was made.

**Docs**
- Developer guide, Sites: "Describe the action in your own words".
- API reference: `stepup_request`, `site_signed`, `stepup_ref`.
- Take over guide: "Where to run the vault". The vault's protections hold only while the agent has no shell on the machine or account where the vault and its key live.

## 0.3.22 (2026-10-04)

**Hearing back from unattended runs**
- `notify_owner(text)` (MCP tool), `AgentClient.notify()` and `authyouragent notify "<text>"` (CLI, reads stdin with `-`): a one-way note to the owner's phone. Up to 600 characters and 12 lines; 20 notes per hour per agent.
- The vault keeps its own record of each session. When the session ends, or the agent stops sending heartbeats, it sends the owner one summary: sites visited, what was approved, denied or let through automatically, and whether sign-out was confirmed. It does not depend on the agent reporting.
- Per-site sign-out reports are sent quietly, and the summary replaces them; they remain as a fallback if the summary fails.
- The MCP server has 20 tools.

**Notification history (app)**
- A bell in the app header with an unread count lists every notification from the last 30 days (up to 300): approvals and their outcomes, notes, session summaries, sign-in requests.
- Tapping a notification opens that entry (`/app?note=…`) or the waiting request (`/app?txn=…`).
- Included in account export and deleted with the account.

**Exact addresses**
- Approval cards, notifications and the session summary name the page's exact address (`demo.authyouragent.com`), not the parent site. Requests are still filed under the site, so approval modes and grants are unchanged. The cloud shows the reported host only if it belongs to the site.

## 0.3.21 (2026-10-03)

- A payment click whose result is unknown is not repeated blind. The vault watches money clicks until the site answers (15 s). With no answer, a 5xx or a failed request, the click returns `result_unknown` (HTTP 504).
- Another money click on that site is then refused until the agent reads a page; after that, the approval card carries a Repeat line (10-minute window).

## 0.3.20 (2026-10-03)

- In Smart mode the owner chooses what a deny pauses: the whole domain (default) or the exact address. The vault sends the exact host with each card; a card without one, from an older vault, pauses the whole domain.
- The approval card drops the item line when it only repeats the button's words.

## 0.3.19 (2026-10-03)

- Approval modes, set by the owner per agent and site: Ask, Smart or Off. Fixed rules, no AI. Money, deleting, posting and account changes always ask. Smart has an hourly limit per site and pauses after a deny. Every automatic approval is logged.
- Approval cards are bound to the amount, item and order read from the button's own form. If the amount changes after approval, the vault does not click.

## 0.3.18 (2026-10-03)

- Vault sign-out runs per host, waits for the page's sign-out form (CSRF token) and for slow sign-out requests.

## 0.3.17 (2026-10-03)

- Vault: numbered page elements (`ref`); new tools `press_key`, `select_option`, `scroll`, `go_back`, `wait_for` and `screenshot`.
- Trusted sites, set by the owner only: `authyouragent vault trust <host> --no-approvals` stops clicks on that host from asking each time; `--private` lets the browser open a host on the owner's own network.
- Docs: Supported standards page; DPoP-bound tokens (RFC 9449); CIBA backchannel confirmations (poll mode); JWT access tokens (RFC 9068) and token introspection (RFC 7662); tested WordPress/WooCommerce recipe.
- Demo Shop: checkout confirmed by the owner via OpenID Connect CIBA, in the shop's own words.

## 0.3.16 (2026-10-03)

- Web Bot Auth: each vault signs its requests with its own Ed25519 key, published per agent at `<label>.agents.authyouragent.com` and emptied on revoke. Site-owner guide.
- Sign in with Auth Your Agent: sessions end when the owner revokes (back-channel logout, refresh tokens, `/oidc/revoke`). Guide and Demo Shop example.
- Developer guide: tested setups for Nextcloud, Forgejo/Gitea, Paperless-ngx and Immich; `preferred_username` / `nickname` claims.
- Home: Try it section with the Demo Shop (demo.authyouragent.com).

## 0.3.15 (2026-10-02)

- Sign in with Auth Your Agent (OpenID Connect). The vault adds the agent's proof when a site's sign-in sends the browser to `/oidc/authorize`. SDK: `AgentClient.oidc_signin` and `oidc_header`.
- Site setup guide: Auth.js, Keycloak/Authentik, WordPress, Django.

## 0.3.14 (2026-10-02)

- `authyouragent approve <site> "<action>"`: exits 0 only when the owner approves on their phone, so a script or CI step can gate on it. SDK: `AgentClient.request_approval`.

## 0.3.13 (2026-10-02)

- `read_page` skips elements inside a block it already read, so links and per-letter spans are not repeated (example.com: 128 lines to 7).

## 0.3.12 (2026-10-02)

- Fix: `read_page` separates lines with real line breaks again; 0.3.11 joined them with a literal `\n`.

## 0.3.11 (2026-10-02)

- The vault recovers when the browser dies: the display is restarted and Chromium relaunched, with the profile and sign-ins kept.
- `read_page` reads `<pre>`, `<blockquote>`, `<dt>` and `<dd>`, and falls back to the page's full text when it is outside the usual elements (it returned nothing for JSON and div-only pages).

## 0.3.10 (2026-10-02)

- Fix: `vault up` accepts the vault's own key copy, or a link to it, as `--key`; it crashed with `SameFileError`.

## 0.3.9 (2026-10-02)

- `read_page` keeps long paragraphs (blocks of 500+ characters were dropped).
- Sign-out finds the control in the account's language and inside shadow roots; Reddit sign-out route.

## 0.3.8 (2026-10-01)

- `list_secrets` and `fill_secret`: fill a username, password or TOTP code from the owner's Bitwarden or Vaultwarden (one shared folder) without the agent seeing it. Exact-origin match, top frame only, field-kind checks.

## 0.3.7 (2026-10-01)

- A run of scripted writes is held until the page goes quiet and asked about once. 0.3.6 asked at the first write and let later writes in the run through after the answer.

## 0.3.6 (2026-10-01)

- Fix: a denied scripted write is blocked before interception ends; it was sent anyway.
- Page-name tabs such as "Release history" no longer ask.

## 0.3.5 (2026-10-01)

- A sign-in page is recognised by whole address parts (`/login`, `/sessions/two-factor`), not by text inside names such as `/authyouragent`. Fixes missed hand-backs and approvals on such pages.

## 0.3.4 (2026-10-01)

- The MCP server starts the vault on first use.
- Clicks that make the page write to the site are held for approval.

## 0.3.3 (2026-10-01)

- Approval requests show the button's words without keyboard-shortcut hints.

## 0.3.2 (2026-10-01)

- The vault asks before any form submit, not only known wording. Search and sign-in steps are exempt.
- Take over ends as done when the relay drops after sign-in.
- Plain-http private addresses report `blocked`.
- Vault removes a stale X display lock at start, so it comes back after a reboot or crash.
- MIT licence file; Dockerfile for the MCP server.

## 0.3.1 (npm, 2026-09-30)

- JS SDK on npm, with the `VERSION` constant matching the package. Trusted publishing on `js-v*` tags.

## 0.3.0 (2026-09-30)

First public release.
- Browser vault: the agent drives a sandboxed browser whose cookies and passwords it cannot read. 11 MCP tools, a session guard, no raw CDP access.
- Take over: the owner signs in from their phone when a site needs a person.
- `request_approval`, `check_agent_status`, `clear_session`.
- Python SDK with agent-side key generation (the cloud stores only the public key), DPoP-bound requests, step-ups, and local site verification (JWKS and a signed revocation list).
- Trusted publishing to PyPI on `py-v*` tags.
