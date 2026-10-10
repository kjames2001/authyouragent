=== Auth Your Agent ===
Contributors: kjames2001
Tags: ai agents, woocommerce, web bot auth, login, checkout
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.2.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Let AI assistants sign in as your customer's approved agent and finish the order. The customer approves on their phone.

== Description ==

People now ask an AI assistant to find a product and order it. When the assistant reaches your sign-in page or your checkout, it stops: it can't solve a CAPTCHA, careful customers won't give it their password, and it has no way to ask them before money moves. The order goes somewhere else, and your analytics never show it as lost.

This plugin adds "Sign in with Auth Your Agent" to your WordPress and WooCommerce sign-in forms.

* **The customer approves the sign-in on their phone.** The assistant gets its own account on your shop, named for what it is (for example "Jarvis (agent of James)"). It never signs in to an existing customer's account and never sees a password.
* **The customer confirms each order, in your words.** Before an agent's order is placed, the customer's phone shows "Pay $52.00 at Lamp Shop for 3 items: Brass lamp, Wick (x2)" and they approve with their fingerprint or face. The approval covers that basket and total only. Works with any payment method, because nothing is charged before it.
* **You can see agent orders.** The orders list has an Agent column. An order the customer approved on their phone shows "Owner approved on phone", and the order page shows the exact text they approved. An agent order placed without that confirmation is marked "Agent order, not confirmed".
* **You can tell signed agents apart.** Any agent that signs its requests with Web Bot Auth (the IETF draft that Cloudflare, Google and others are standardising) is checked on every request, from any provider, not only Auth Your Agent. Settings shows which agents visited and when. Block an agent, allow it, or let in only the agents you have allowed. Orders an agent places while signing are labelled with its address.
* **Withdrawing access ends the session.** When the customer withdraws the assistant's access, it is signed out of your shop at once (OpenID Connect Back-Channel Logout), or within 10 minutes if that message cannot reach you.
* **Ordinary customers notice nothing.** People sign in and check out as before.

Standard OpenID Connect (authorization code with PKCE, and CIBA for order confirmation) and Web Bot Auth (HTTP Message Signatures, RFC 9421). No other plugins or libraries needed.

== Installation ==

1. Install and activate the plugin.
2. Open Settings > Auth Your Agent. It shows this site's redirect URI and sign-out URI.
3. In your Auth Your Agent account (authyouragent.com, Sites), add your site with those two addresses. Copy the client ID and secret into the plugin settings and save.
4. The button appears on the sign-in forms. Use the `[authyouragent_button]` shortcode to place it elsewhere.

== Frequently Asked Questions ==

= Does this let bots into my shop? =

No more than now. It lets an assistant that a real customer has approved sign in as that customer's agent, and it asks the customer before every order. Your existing bot protection stays in place for everyone else.

= What role do agent accounts get? =

Customer (or your site's default role), configurable. Roles that can manage the site or other users cannot be chosen.

= Can I change the confirmation text? =

Yes, with the `authyouragent_confirm_message` filter. It must stay one line of at most 120 characters.

= What does a signed agent prove, and what not? =

A verified signature proves the request came from whoever holds that agent's key, and the agent's address is where its keys are published. It does not tell you who the person behind it is. Ordinary visitors never send a signature, so they are never blocked by these settings. An agent that stops signing looks like any other visitor: blocking a signed agent stops that agent, not every bot.

= Does checking signatures slow my site down? =

Only signed requests are checked. The agent's key list is fetched once and cached for as long as it says (at least a minute). Requests without a signature skip the check entirely.

= Is there a cost? =

Free during early access. See authyouragent.com/for-shops.

== External services ==

This plugin connects to Auth Your Agent (https://authyouragent.com, or your own server if you change the provider address), which signs agents in and asks customers to confirm orders.

* When an agent clicks the sign-in button: the browser is sent to Auth Your Agent; the site then exchanges a one-time code for the agent's identity.
* When an agent places an order: the site sends the confirmation text (amount, shop name, item names) and the agent's identifier, and checks for the customer's answer.
* Hourly: the site fetches the provider's public settings and signing keys.
* When a request carries a Web Bot Auth signature: the site fetches the signing agent's public key list from the address the agent names (for example https://a-....agents.authyouragent.com, or another provider's address). Only public HTTPS addresses are fetched, with a 5 second and 64 kB limit, and redirects are not followed. Nothing about the request is sent.

No data about ordinary visitors or customers is sent. Terms: https://authyouragent.com/legal/terms. Privacy: https://authyouragent.com/legal/privacy.

== Changelog ==

= 0.2.0 =
* Signed agents: checks Web Bot Auth signatures from any agent, lists the agents that visited, block / allow per agent, an allow-only mode, and an option to refuse forged signatures. Unsigned visitors are never affected.
* Orders: an Agent column on the orders list, an "Owner approved on phone" badge on orders the customer confirmed, and a label on orders placed by a signed agent.

= 0.1.0 =
* First release: sign-in for agents, order confirmation on the customer's phone, back-channel sign-out.
