# Case study: ten days of real use

This is the first real account on Auth Your Agent: the author, James, and his own AI agent, Jarvis. Jarvis runs on [Hermes Agent](https://github.com/NousResearch/hermes-agent). From 26 September to 6 October 2026, Jarvis did James's errands on public websites through the vault. The errands included posting and replying on Reddit, opening pull requests on GitHub, and listing the project in directories. Every number below comes from the production audit log, and none were rounded up. It is one person with one agent, so read it as a field report, not a survey.

## The numbers

- **62 take overs.** Jarvis hit 62 sign-in walls, CAPTCHAs or texted codes it could not pass alone. These were on Reddit (39), GitHub (8), Glama (7) and a few other sites. James finished 51 of them from his phone. The median time from the request to "done" was **53 seconds**. He cancelled 6, 3 expired while he was away, and in 2 the agent gave up waiting.
- **70 click approvals, 15 of them denied.** Each time Jarvis was about to post, submit or change something, the click waited for James on his phone. He approved 55 and denied 15. A denial cost nothing: the click simply did not happen, and Jarvis stopped and asked. (Separately, James approved 7 site-access requests.)
- **7 sign-ins from a saved login.** James saved the Reddit login in his own Vaultwarden. From then on, the vault typed it in itself. Jarvis only named the item, and never saw the value.
- **4 clicks from a pre-approved plan, with no prompt.** This was the run on 6 October, shown on the home page and in a video. Jarvis submitted a plan at 03:12 for four Reddit posts between 10:00 and 12:00. James read the full text of each post and approved it once with his passkey. At 10:06 Jarvis signed in with the saved login, posted all four by 10:11, and signed out at 10:12. Each click went through only because a fingerprint of the text it was sending matched the text James had approved.

## What a stranger found

A Reddit user (Acrid) asked a question in a comment under the project's launch post. What if a page changes *where* a form sends after the person approves the click? He was right: the vault re-checked the amount and the text, but not the destination. Version 0.3.27 fixed this. The vault now re-reads the form's destination before clicking and refuses if it has changed. If a form sends to a different site, the approval card says so in a "Sends to" row. The fix and its tests shipped, and then the reply to him explained what changed.

## What did not work

- **Nine sessions did not sign out cleanly.** All were on Reddit, and all happened when the vault was stopped or replaced mid-session. In each case the owner was told where to end the session by hand. The vault cannot sign out after it has been stopped, so a clean shutdown matters.
- **Take over is the slow path.** It works, but each one needs the person's attention. Saving the login turned most Reddit take overs into silent sign-ins. That was the change that made the scheduled run possible.
- **Smart mode let three clicks through on a guess, and two were Reddit comments.** It judged from the button word, and old Reddit's comment button says "save", which Smart mode treated as something that can be undone. James had approved the text in chat, but his phone never showed it. Since 6 October, any click that sends typed text counts as posting and asks, whatever the button says.

## Why it matters

The useful finding is the shape of the work, not the totals. Early on, a Reddit errand needed James twice: once to sign in, once to approve. By the tenth day, the routine work (a known site, known text, a known time) needed him once, the night before or the morning of. The work that still asks is the work that should: anything new, anything changed, and every payment.

## Try it

The vault, the Python SDK and the MCP server are MIT licensed: `pipx install "authyouragent[mcp]"`. See [For AI agents](/docs/agents) for the tools, [Take over](/docs/developers/takeover) for approval modes and plans, and the [source on GitHub](https://github.com/kjames2001/authyouragent).
