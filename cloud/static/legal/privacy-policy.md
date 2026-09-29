# Auth Your Agent Privacy Policy

**Auth Your Agent** — last updated 2026-09-26
Controller: the operator of authyouragent.com (the operator's jurisdiction)
Governing law: **the applicable Data Protection Act** (in force 14 January 2025); GDPR where you are in the EEA/UK

## 1. What Auth Your Agent does
Auth Your Agent is a free identity service for authorizing AI agents. You (the human) register the software agents you use, and you authorize each agent to act on your behalf on specific websites — approval happens on your phone with your fingerprint/face (a passkey). The websites see that a real, accountable human stood behind the agent, and can revoke access at any time.

## 2. Data we process and why (the applicable DPA ss. 4–11; GDPR Art. 6)

| Data | Purpose | Lawful basis | Retention |
|---|---|---|---|
| Email, display name, password hash (or SSO identity) | Account, sign-in, agent management | Performance of contract (s. 9(1)(b)); consent | Until account deletion |
| Phone number (sometimes received from your SSO provider) | Out-of-band identity verification & recovery | Performance of contract; consent (where we send codes) | Until cleared |
| **Passkey / WebAuthn credential** | Phone approval — the trust anchor | Performance of contract | Until you clear it |
| Agent **public** keys (never private keys) | Verify your agents' requests | Performance of contract | Until agent removed |
| Grants: which agent, which site, which scopes, which user-info fields | Your per-site authorizations | Performance of contract; **consent for user-info fields** (approval card) | Until revoked |
| **User-info disclosed to sites** (name/email/phone, only what you consented per site) | The site's on-behalf-of actions | **Your explicit per-site consent** (s. 8 / GDPR Art. 6(1)(a)) | Until you narrow or revoke |
| Append-only audit log (who, what, when, outcome) | Your right to see and explain your agents' actions; site accountability | Legitimate interest (s. 9(1)(f)); your benefit | 24 months, then archived |
| FCM / web-push subscription tokens | Deliver approval notifications to your phone | Consent (you enable push) | Until disabled |

### Biometric data — the key fact
Your fingerprint/face is matched and stored **on your phone's secure hardware** (secure element / TEE). Auth Your Agent receives a **signed assertion**, not your biometric. We never see, store, or process your biometric template. (the applicable DPA s. 30; GDPR "biometric data" recitals 51–53.)

## 3. The user-info disclosure (Auth Your Agent's scope model)
A website declares which of your fields it wants (e.g. name, email, phone). Your **phone approval is the explicit consent** for exactly that set, and it is shown on the approval card. Those values are snapshotted into a signed, short-lived token the site reads. You can **narrow** what a site sees at any time (removing a field takes effect on the agent's next token); adding a field back requires a new phone approval. A site that never asked for your phone learns nothing about it.

## 4. Cross-border transfer (the applicable DPA Part XIV, s. 74)
Auth Your Agent is established in the operator's jurisdiction. Its systems run on our own servers in the **United States** (racknerd VPS, `authyouragent.com`). This is a transfer to a third country. Our safeguards:

- **Local copy (s.74 proviso):** a copy of your personal data transferred abroad is kept in the operator's jurisdiction (an encrypted replica of our database on locally-based storage) for the period of processing.
- **Explicit, informed consent (s.78(a))** given at signup and per user-info grant, captured in this policy and the approval flow.

We keep our databases on our own, self-hosted, auditable infrastructure — we are not a reseller and do not share your data with third parties for their marketing.

> If the Commission's adequacy orders (s. 75) cover the destination, this transfer also rests on adequacy; consent + the s.74 local copy are our current, documented basis.

> **No registration to file:** the 2024 Act imposes no controller registration or pre-processing notification duty (unlike the repealed 2018 Act); our obligation is the internal record of processing (s. 60), which we maintain and can produce on request.

## 5. How long we keep it
- Active account data: until you delete your account (we process it within 30 days).
- Audit log: 24 months active, then anonymized/archived.
- Revoked grants: retained as a record of your consent history, linked to the agent, until account deletion.

## 6. Your rights (the applicable DPA Part VIII; GDPR Chapter III)
You may, at any time, free of charge:
1. **Access** a copy of your personal data (email, phone, agents, grants, audit log, consent records) — via the Auth Your Agent app ("Export my data") or by request.
2. **Rectify** inaccurate data.
3. **Erase** your data (account deletion) — a copy is kept only as far as required by law (e.g. the append-only audit).
4. **Restrict** processing (revoke a grant / agent).
5. **Object** to processing based on legitimate interests.
6. **Data portability** of the data you provided, in a structured, machine-readable form.
7. **Withdraw consent** for user-info disclosure per site (narrow in the app) or for push.

To exercise a right: use the Auth Your Agent app, or email **privacy@authyouragent.com**. We respond within **30 days** (GDPR: 1 month).

## 7. Security (the applicable DPA Part XI)
- TLS everywhere; HSTS at the edge (Let's Encrypt).
- DPoP key-bound tokens (RFC 9449) — a stolen token is useless without the agent's key.
- Short-lived, audience-scoped access tokens (≤ 15 min); revocable refresh tokens.
- Passkey-signed (hardware) approvals; the cloud never holds private keys.
- Role-based, least-privilege; append-only audit log.
- Rate limiting and per-key rotation.
Full detail in our **Security Whitepaper**.

## 8. Breach notification (s. 63)
If a personal data breach is likely to risk your rights, we notify the **Information and Data Protection Commission** without undue delay and, where feasible, within **72 hours**, and we tell you where the risk is high.

## 9. Children (s. 29)
Auth Your Agent is a general-service product. Processing a child's personal data in the offer of an information-society service requires parental consent; a child of **16** may consent in the prescribed manner. We do not knowingly process under-13s.

## 10. No sale of data
We do not sell your personal data. The audit log and consent records are our product's accountability data and are yours to inspect.

## 11. Changes
Material changes to this policy are announced in the app before they take effect. Consent for user-info is always per-grant and re-asked when a site wants more.

---
*This policy is the controller's record under applicable transparency duties and supports the the applicable Record of Processing Activities. Regulatory contact: your national data protection authority.*
