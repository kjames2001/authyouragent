# Supported standards

Auth Your Agent is built on published standards, so any library that speaks them works without an Auth Your Agent SDK. This page lists what is supported, what is not, and where each standard is used. The live server metadata is at [/.well-known/openid-configuration](/.well-known/openid-configuration).

## Sign in with Auth Your Agent (sites)

| Standard | What it does here |
|---|---|
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | Authorization code flow. ID tokens signed with RS256. `nonce`, `prompt=none` and `prompt=login`, `max_age`, `auth_time`, `acr` and `amr`. |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Metadata at `/.well-known/openid-configuration`, keys at `/oidc/jwks`. |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) OAuth server metadata | The same metadata at `/.well-known/oauth-authorization-server`. |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) OAuth 2.0 | Client authentication with `client_secret_basic`, `client_secret_post`, or `none` for public clients. Bearer tokens in the header or the form body. |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) PKCE | `S256` only. Required for public clients. |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) issuer in the response | The authorization response carries `iss`. |
| Pairwise subject identifiers (OpenID Connect Core 8.1) | `sub` (the owner) and `act.sub` (the agent) differ per site, so sites cannot match people across sites. |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) `act` claim | Names the agent acting for the owner. Sent with the `profile` scope. |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access tokens | Access tokens are signed JWTs (`typ` `at+jwt`) your API can check offline. |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) token introspection | `POST /oidc/introspect`, for confidential clients. Revoked and ended tokens report `{"active": false}`. |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) token revocation | `POST /oidc/revoke`. |
| Refresh token rotation | A new refresh token on every refresh. Reusing an old one ends the sign-in. |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP | Optional. A site that sends a proof gets tokens bound to its key (`cnf.jkt`). The `dpop_jkt` parameter binds the authorization code. Algorithms: ES256, RS256, EdDSA. |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint | Used for DPoP key binding. |
| [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | `POST /oidc/bc-authorize` lets a site ask the owner to confirm something on their phone, with its own message. Poll mode. |
| [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | When the owner revokes the agent, your site receives a signed `logout_token` with the session's `sid`. |

How to use each one: [Accepting agents on your site](/docs/developers/sites).

### Conformance

We ran the OpenID Foundation's own [conformance suite](https://gitlab.com/openid/conformance-suite) against the production server. The discovery configuration plan passed. In the Basic OP plan 21 modules passed. The 5 that did not pass need a person in the loop (a phone tap for `prompt=login` and `max_age=1`, screenshots of two error pages) or a state our test harness cannot create. None of them pointed to a server bug.

Auth Your Agent is **not** formally OpenID Certified. That is a separate application to the OpenID Foundation.

### Not supported

- Request objects (`request`, `request_uri`) and pushed authorization requests (PAR). The server returns `request_not_supported`.
- Dynamic client registration (RFC 7591). Register sites in the dashboard.
- Implicit and hybrid flows. Only `response_type=code` is supported.
- RP-initiated and front-channel logout. Use back-channel logout.
- The ping and push modes of CIBA. Only poll mode is supported.
- Mutual-TLS client authentication and `private_key_jwt`.

## Agents and the vault

| Standard | What it does here |
|---|---|
| [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) (passkeys) | Owners approve sign-ins and sensitive actions with a passkey on their phone. |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP | Each agent call to a site carries a proof signed by the agent's key. See the [HTTP API reference](/docs/developers/api). |
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures and [Web Bot Auth](https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/) (IETF draft) | The vault signs every request it sends with its own Ed25519 key. See [Recognising agents](/docs/developers/web-bot-auth). |
| [Model Context Protocol](https://modelcontextprotocol.io/) | The `authyouragent` MCP server gives agents the vault's tools. Sites can turn an OpenAPI 3 description into MCP tools. See [MCP tools for your site](/docs/developers/mcp). |
