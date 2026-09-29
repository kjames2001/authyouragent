# Auth Your Agent Terms of Service

**Auth Your Agent** — effective 2026-09-26
These Terms govern use of the Auth Your Agent identity service. By creating an account you
agree to them.

## 1. The service
Auth Your Agent is an identity broker: a human (you) registers AI **agents**, and
authorizes them to act on your behalf on **sites** that integrate Auth Your Agent. Auth Your Agent
issues to each authorized agent a short-lived token scoped to what you
approved. Auth Your Agent does **not** act on the internet on your behalf — your agents do;
Auth Your Agent only proves who/what the agent is.

## 2. Accounts & humans
- You are the **human of record** for every agent you register and every
  authorization you approve. You are responsible for them.
- Auth Your Agent is currently **free**. We may introduce paid tiers later with notice.
- One human may have many agents; each agent belongs to exactly one human.

## 3. You approve each delegation
- An agent can only do what you have **explicitly approved** in your phone's
  Auth Your Agent app (a WebAuthn gesture in the phone's secure hardware).
- **Phone approval is consent.** Approving a grant also consents to disclosing
  the specific user-info fields you were shown (e.g. your name) to that site.
- You can **revoke** any agent or approval at any time, from the app. Revoked
  agents' tokens stop being accepted (after their short lifetime).
- You can **narrow** the user-info fields a site can see without re-approving;
  **widening** them requires a fresh phone approval.

## 4. Agent behavior & liability
- Your agents act autonomously on approved tasks. **You** are responsible for
  the actions your agents take on sites, to the same degree as if you did
  them yourself.
- Auth Your Agent is an identity layer, not an escrow or a guarantee of agent success. We
  are not liable for decisions an agent makes within your approval.
- Sites that integrate Auth Your Agent remain responsible for what their own systems do
  with your data.

## 5. Security responsibilities
- Keep your **phone and the passkeys on it** secure. Auth Your Agent's trust anchor is the
  phone's secure hardware (biometrics/PIN) — if that is compromised, an
  attacker can approve things on your behalf.
- Use screen lock. Auth Your Agent requires the phone to be unlocked to approve.
- Report lost devices to us (support@authyouragent.com) so we can
  invalidate their session.

## 6. Data
Our Privacy Policy (see footer) governs data. In short: minimal data, no ads,
no sale, no behavioural tracking.

## 7. Acceptable use
- Don't use Auth Your Agent to impersonate other humans.
- Don't run agents that make mass, automated, unsolicited requests to sites
  (anti-spam).
- Don't scrape Auth Your Agent or reverse-engineer its keys.
- No use in a way that materially degrades the service for others.

## 8. Suspension & termination
- We may suspend an account or an individual agent for misuse or a
  security threat, with notice where practicable.
- You may delete your account at any time (Settings → Delete account).
- On termination, agents you registered stop working (their tokens are
  rejected); we retain your data per the Privacy Policy retention schedule.

## 9. Service availability
- We run Auth Your Agent on a single region with daily encrypted
  backups. We target high availability but this is a small service: we
  do not SLA-guarantee uptime in v1.
- We may take down for maintenance with reasonable notice.

## 10. Changes to these Terms
- We may update these Terms; material changes get notice in the app/email.
- Continued use after a change means you accept it. If you disagree, delete
  your account.

## 11. Law & disputes
- **Botswana law** governs (the service is established in Gaborone,
  Botswana). The Information and Data Protection Commission and Botswana
  courts are the default forum.
- For users in other jurisdictions, see the **Market Entry Notes** —
  jurisdiction-specific addenda apply (e.g. GDPR for EU/UK users, PIPL for
  PRC users). Those addenda prevail over these general terms on conflict.

## 12. Contact
support@authyouragent.com · authyouragent.com
