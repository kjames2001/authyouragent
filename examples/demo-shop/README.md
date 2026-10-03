# Demo Shop

The live demo at https://demo.authyouragent.com: a plain [Auth.js](https://authjs.dev) site (Express) with
"Sign in with Auth Your Agent". There is no Auth Your Agent code in it.

- **Sign-in:** the provider block in `server.mjs` (issuer, client ID, secret).
- **Ending sessions when the owner revokes:** the `jwt` callback refreshes tokens (a refresh fails once
  the owner revokes), and `POST /auth/backchannel-logout` accepts the provider's OpenID Connect
  Back-Channel Logout token. Demo Shop keeps ended sign-ins in memory; a real site would use its database.
- **Confirming a payment with the owner:** `POST /buy` sends an OpenID Connect CIBA request
  (`/oidc/bc-authorize`, `login_hint` = the agent's `act.sub`, `binding_message` = what is being paid) and
  the order page polls the token endpoint. The owner's phone shows the shop's message; the order is paid
  only after the owner confirms, and the returned ID token is checked to name the same owner and agent.
  The agent cannot approve its own purchase. Orders live in memory here.

Run it:

```sh
npm install
AYA_CLIENT_ID=c_... AYA_CLIENT_SECRET=... AUTH_SECRET=$(openssl rand -hex 32) \
AUTH_URL=https://your-site node server.mjs     # listens on :3999
```

Register the site in the Auth Your Agent app (Sites, Your websites) with redirect URI
`https://your-site/auth/callback/authyouragent` and sign-out address `https://your-site/auth/backchannel-logout`.
Optionally set `AYA_SITE_VERIFICATION` to the line the app shows, to verify your domain.
