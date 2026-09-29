# Install the Android app

The Android app is the same service as the website, with these additions:

- passkeys go through Android's own credential system, so your fingerprint prompt looks native and works with Google Password Manager and other passkey providers
- links to authyouragent.com open in the app
- an optional lock: the app asks for your fingerprint, face or PIN when you open it
- pull down to refresh; a clear screen with a **Try again** button when the phone is offline
- **Download my data** saves the file to your Downloads folder

Notifications are not available in the app yet. Until they are, keep the app open when you expect a request, or turn on notifications in Chrome at [authyouragent.com/app](/app) as well.

## Install

The app is not in the Play Store yet. Your administrator sends you an install file (APK).

1. Open the file on your phone.
2. If Android asks, allow your browser or file manager to install apps.
3. Open **Auth Your Agent** and sign in.
4. Open **Account** and tap **Add passkey**. Passkeys made in Chrome on the same phone also work in the app, as long as they were saved to the same account (for example Google Password Manager).

Requirements: Android 9 or newer.

## App settings

**Account → App settings** has:

- **Require unlock when opening.** Off by default. When on, the app asks for your fingerprint, face or phone PIN whenever you open it after more than a minute away. Your phone must have a screen lock.
- **Help**: this guide.
- **Sign out and erase data on this phone**: ends your session and removes everything the app stored on this phone. Your account, agents and passkeys are not affected.

## Updating

Install the new file over the old one. Your sign-in and passkeys are kept.

## If a passkey prompt fails

The app explains the cause in plain words. The common ones:

- **No passkey for this account on this phone.** Add one under **Account**.
- **A passkey prompt is already open.** Finish or cancel it first.
- **Screen lock is off.** Android only allows passkeys when the phone has a screen lock.
- **Your passkey store is locked.** Usually a Chrome sync passphrase on your Google account. Remove it, or choose another passkey provider such as Samsung Pass.
