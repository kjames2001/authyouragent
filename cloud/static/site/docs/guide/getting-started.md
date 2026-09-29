# Getting started

Auth Your Agent lets an AI agent act for you on a website without ever holding your password. You approve each agent from your phone, and you can take access back at any time.

This guide takes about five minutes.

## 1. Create your account

1. Open [authyouragent.com/app](/app) in your phone's browser, or install the Android app (see [Install the Android app](/docs/guide/android)).
2. Tap **Create account**. Enter your email, a password of at least 8 characters and a display name.

Your display name is what sites see if you agree to share it. You can change it later under **Profile**.

When you first sign in, a short tour walks through every tab and what each button does. You can replay it any time from **Account → Help → Show the tour again**.

## 2. Add a passkey on your phone

A passkey lets you approve requests with your fingerprint or face. It is the safest way to approve, and it is required for risky actions such as applying for a job or paying.

1. Open the **Account** tab and, under **Security**, tap **Add passkey**.
2. Your phone asks for your fingerprint, face or screen lock. Confirm.
3. **Passkey on this device** changes to **Enabled**.

Passkeys belong to one phone or password manager. If you use a second phone, add a passkey on that phone too.

## 3. Turn on notifications

In the **Account** tab, tap **Enable notifications** and allow them when your browser asks. Approval requests then reach you even when the page is closed.

In the Android app, notifications are not available yet. The app shows new requests within a few seconds while it is open.

## 4. Connect your first agent

An agent needs its own key before it can ask for anything. There are two ways to set one up:

- **The agent makes its own key (recommended).** The agent's developer runs a command that creates the key on the agent's machine and prints a public part. You paste that into **Agents → Add an agent**. The private key never leaves the agent's machine.
- **Auth Your Agent makes the key.** In **Add an agent**, open **Other ways to add a key**, tick **Create the key here instead**, and copy the key shown once. You must hand this file to the agent yourself. Use this only when the agent can't generate its own key.

## 5. Approve a request

When the agent first wants to use a site, a card appears in the **Approvals** tab, and a notification arrives if you turned them on. The card shows:

- which agent is asking
- which site it wants
- what it wants to do there (for example "list jobs", "apply")
- what information about you the site would receive, if any
- how long the request stays open (5 minutes)

Tap **Approve** to confirm with your passkey, or **Deny**. If you do nothing, the request expires.

Optional: **Limit this access** lets you make the access end after a set time (for example 1 day), or after a number of sensitive actions.

Next: [Approving requests](/docs/guide/approving) explains the different kinds of request and the ways to approve them.
