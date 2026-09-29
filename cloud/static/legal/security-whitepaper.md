# Auth Your Agent Security Whitepaper

**Auth Your Agent** — v1.0, 2026-09-26.
How Auth Your Agent keeps the trust in "agent identity". Read this if you're a site
integrating Auth Your Agent, a regulator, or a user who wants to know why your phone's
biometric is the anchor and nothing else is.

## 0. The problem
An AI agent acting on your behalf on a website needs to prove three things:
(a) it is **you** (or your agent), (b) it is **this** agent, (c) it is allowed
**this much** right now. Traditional session cookies prove none of these — a
cookie is an anonymous bearer token. Auth Your Agent replaces that with a hardware-rooted,
scoped, expiring identity.

## 1. Trust anchor: the phone's secure hardware
- The **only** thing that can create an Auth Your Agent credential or approve an action is
  a gesture in the phone's **secure element** (TEE / StrongBox) via the
  platform's passkey API (WebAuthn). On the desktop this is a platform
  authenticator; on Android, Credential Manager backed by TEE/StrongBox +
  biometrics.
- The **private key never leaves the secure element**. Auth Your Agent's servers never see
  it. A network-level attacker who captures Auth Your Agent's whole database still cannot
  sign an assertion.
- Approvals require the phone **unlocked and present** — a stolen-but-locked
  phone cannot silently approve.
- This is the same hardware root browsers already use for "Sign in with
  Apple / Google / 1Password". Auth Your Agent adds a **phone-approval step** on top for
  agent delegation, so a credential being stored is not a credential being
  spent.

## 2. What a token actually is
When you approve an agent acting on a site, Auth Your Agent's cloud signs a **short-lived
access token** (≤15 minutes). It carries:
- **iss / aud / exp / jti** — standard JWT claims. `aud` is the *site* (so a
  token minted for site A is useless to site B).
- **agent_id** — which agent.
- **scopes** — what it may *do* (e.g. `read:jobs`, `write:applications`).
- **user_info** — the *specific* user fields you consented to disclose (e.g.
  `user:name`), snapshotted at approval and signed in. The site reads it from
  the token; it cannot forge it, and it is the exact set you approved.
- **DPoP binding** — the token is cryptographically bound to a per-connection
  DPoP proof, so a captured token can't be replayed by another client.

Sites verify locally (JWKS) or via the cloud. A revoked agent's tokens simply
expire (≤15 min) and are then rejected on step-up.

## 3. Phone-approval = consent, not just auth
- Approving a grant is a **WebAuthn assertion** — you are cryptographically
  saying "yes, I approve this".
- The approval UI shows the site, the agent, the **scopes**, and the
  **user-info fields** to be shared. You see exactly what you're consenting to.
- Consent is **narrowable**: strip a field from a grant without re-approving.
  Widening requires a fresh phone approval. You can never *accidentally give
  more* — only take back.

## 4. Credential & key management
- **Cloud signing keys** are held by the cloud service; a **JWKS rotation**
  endpoint publishes current + previous public keys so sites verify through
  rotations without a gap.
- **Agent keys** are held by the agent runtime (not the phone, not the cloud).
- **VAPID keys** (web push) and **FCM** (Android push) are separate from
  signing — push can only *wake* you; it cannot sign.
- Private keys are stored **AES-256 encrypted at rest** (passphrase-derived),
  and the database is encrypted at rest by the host.

## 5. Transport & web surface
- TLS everywhere (Let's Encrypt on `authyouragent.com`); HSTS.
- The PWA is **100% self-hosted, zero third-party scripts/CDNs**. A strict
  **Content-Security-Policy** (`default-src 'self'`, `connect-src 'self'`,
  `frame-ancestors 'none'`) means any future XSS cannot exfiltrate to a remote
  host.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- The Android app's WebView hardens further: `allowFileAccess=false`,
  `allowContentAccess=false`, `MIXED_CONTENT_NEVER_ALLOW`, and a native
  WebAuthn bridge that routes `navigator.credentials.*` to the OS Credential
  Manager (hardware-backed) rather than trusting the web engine.

## 6. Data stores & backups
- Postgres/SQLite at the cloud; **daily encrypted backups**, retained and
  versioned.
- The `fcm_tokens` and `push_subs` tables store only push subscription
  endpoints — not identities, not keys.
- Session cookies are `HttpOnly; Secure; SameSite=Lax`.

## 7. Failure & incident handling
- **72-hour breach notification** to the regulator (and affected users where
  they're impacted), per Botswana DPA 2024 (and GDPR where applicable).
- A compromised **phone** → re-pair / re-register; its old credential stops
  approving. A compromised **cloud** → rotate the signing key via JWKS; held
  DB dumps can't mint or sign assertions.
- We run in a **single region**. Cross-region failover is on the
  roadmap; until then, backups are the continuity mechanism.

## 8. What Auth Your Agent does NOT do
- No advertising, no data sale, no behavioural tracking, no third-party
  analytics.
- We do not store your agents' *task results* or the *content* of what they
  do on sites — only the identity/scoping metadata.
- We are not an escrow, not a notary, and not a guarantee that an agent did a
  good job.

## 9. Audit & transparency
- We maintain a **Record of Processing Activities** (RoPA) and a
  Privacy Policy that states, per category, what we collect, why, and how
  long.
- We publish the JWKS for third parties to verify our signatures.
- We intend to commission an **independent penetration test** before any
  paid-tier launch and to disclose a summary.
