=== Auth Your Agent ===
Contributors: authyouragent
Tags: ai agents, woocommerce, openid connect, login, checkout
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Let AI assistants sign in as your customer's approved agent and finish the order. The customer approves on their phone.

== Description ==

People now ask an AI assistant to find a product and order it. When the assistant reaches your sign-in page or your checkout, it stops: it can't solve a CAPTCHA, careful customers won't give it their password, and it has no way to ask them before money moves. The order goes somewhere else, and your analytics never show it as lost.

This plugin adds "Sign in with Auth Your Agent" to your WordPress and WooCommerce sign-in forms.

* **The customer approves the sign-in on their phone.** The assistant gets its own account on your shop, named for what it is (for example "Jarvis (agent of James)"). It never signs in to an existing customer's account and never sees a password.
* **The customer confirms each order, in your words.** Before an agent's order is placed, the customer's phone shows "Pay $52.00 at Lamp Shop for 3 items: Brass lamp, Wick (x2)" and they approve with their fingerprint or face. The approval covers that basket and total only. Works with any payment method, because nothing is charged before it.
* **You can see agent orders.** Each one carries a note naming the agent and the text the customer confirmed.
* **Withdrawing access ends the session.** When the customer withdraws the assistant's access, it is signed out of your shop at once (OpenID Connect Back-Channel Logout), or within 10 minutes if that message cannot reach you.
* **Ordinary customers notice nothing.** People sign in and check out as before.

Standard OpenID Connect (authorization code with PKCE, and CIBA for order confirmation). No other plugins or libraries needed.

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

= Is there a cost? =

Free during early access. See authyouragent.com/for-shops.

== External services ==

This plugin connects to Auth Your Agent (https://authyouragent.com, or your own server if you change the provider address), which signs agents in and asks customers to confirm orders.

* When an agent clicks the sign-in button: the browser is sent to Auth Your Agent; the site then exchanges a one-time code for the agent's identity.
* When an agent places an order: the site sends the confirmation text (amount, shop name, item names) and the agent's identifier, and checks for the customer's answer.
* Hourly: the site fetches the provider's public settings and signing keys.

No data about ordinary visitors or customers is sent. Terms: https://authyouragent.com/legal/terms. Privacy: https://authyouragent.com/legal/privacy.

== Changelog ==

= 0.1.0 =
* First release: sign-in for agents, order confirmation on the customer's phone, back-channel sign-out.
