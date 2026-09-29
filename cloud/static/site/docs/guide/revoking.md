# Revoking access

You can take back anything you approved, at any time, from the app. There are three levels, from narrowest to widest.

## 1. Revoke one site

**Sites → Revoke** on the site's card.

The agent can no longer use that site. Its other sites are not affected. Sites that check with Auth Your Agent live refuse the agent's next request. Sites that keep a local, signed copy of the revocation list refuse it within about a minute.

To use the site again, the agent has to ask you again.

## 2. Change what a site can see about you

If a site receives information about you (for example your name), **Sites → Change shared information** lets you untick fields. The change applies to the agent's next pass, within 10 minutes.

You can only remove fields here. Adding a field needs a new approval, because the site did not have your consent for it before.

## 3. Block an agent everywhere

**Agents → Block everywhere** on the agent's card.

The agent is refused on every site, and it can't ask you for anything new. Its key and its history are kept, so you can undo this with **Unblock**.

Use this when an agent is misbehaving, or when you are not sure whether its key has been stolen.

## 4. Remove an agent

**Agents → Remove**.

Everything **Block everywhere** does, plus the agent is deleted and its key stops working permanently. This can't be undone. To use the same program again, add it as a new agent with a new key.

## What happens to requests in progress

A request that is already waiting for your approval is cancelled when you revoke the agent. A sensitive-action approval already given, but not yet used, stops working at the same time as the agent's access.

## How fast it takes effect

| Site checks with us | Time until the agent is refused |
|---|---|
| Live, on every request (the default) | The next request |
| From a local copy of the revocation list | Within about a minute |

Passes already issued to the agent last at most 10 minutes, and sites must refuse them once they see the revocation.
