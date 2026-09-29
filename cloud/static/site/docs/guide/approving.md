# Approving requests

Every time an agent wants something new, it has to ask you. Requests appear in the **Approvals** tab (a red number shows how many are waiting) and, if notifications are on, on your phone's lock screen.

## Two kinds of request

**Access to a site.** The agent wants to start using a site, for example to read job listings. If you approve, the agent can do the listed things on that one site until you revoke it. Its passes last 10 minutes each and are renewed automatically in the background.

**A sensitive action.** The site has marked some actions as risky, such as applying for a job, paying or deleting something. Even if the agent already has access to the site, each of these actions needs a fresh approval. That approval works once, for 60 seconds.

## What the card tells you

- **Agent**: the name you gave the agent when you added it.
- **Site**: the website the agent wants to use.
- **Permissions**: what the agent will be able to do there. The site defines these names.
- **Shared information**: anything about you the site would receive, such as your name or email. Nothing is shared unless it is listed here.
- **Time left**: requests close after 5 minutes if you do nothing.

## Ways to approve

| Method | Access to a site | Sensitive action |
|---|---|---|
| Passkey (fingerprint, face or screen lock) | Yes | Yes |
| Sign in again with Google or Microsoft | Yes | Yes |
| Your Auth Your Agent password | Yes | No |

The passkey is the recommended method. Password approval exists so that you are never locked out if your passkey is on another phone. For that reason it can't approve sensitive actions. Password approval is limited to five attempts in five minutes per account, to stop guessing.

Google and Microsoft approval only appear once the service has sign-in with those providers switched on, and only if your account is linked to one. They always ask you to sign in again, even if you are already signed in with them.

## Denying

Tap **Deny**. The agent is told straight away and can't use that request again. Denying does not block the agent; it can ask again later. To stop an agent completely, see [Revoking access](/docs/guide/revoking).

## If you have more than one phone

Every signed-in phone and browser with notifications on receives the request. The first one to answer wins, and the card disappears from the others.

## Notification did not arrive

- Open the app. Requests always appear there within a few seconds, notification or not.
- In a browser, check **Account → Security → Notifications** says **On**. If not, tap **Enable notifications**.
- In the Android app, notifications are not available yet; keep the app open while you expect a request.
