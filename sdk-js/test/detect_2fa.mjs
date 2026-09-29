import { loginFinished } from "../src/takeover.js";
import { chromium } from "playwright-core";
const blocked = ["<input type=password>","<input autocomplete=one-time-code>","<label>Enter the 6-digit code</label><input name=code inputmode=numeric maxlength=6>","<input id=verificationCode>",
 "<input maxlength=1><input maxlength=1><input maxlength=1><input maxlength=1><input maxlength=1><input maxlength=1>",
 "<h2>Approve sign in request</h2><p>Open your Authenticator app</p>","<h1>2-Step Verification</h1><p>Check your phone.</p>","<h1>Verify it’s you</h1>"];
const done = ["<h2>Welcome back</h2>","<label>Postcode</label><input name=postcode inputmode=numeric maxlength=6><input name=promo_code>","<input type=search name=q>","<input type=password style=display:none>"];
const b = await chromium.launch({ executablePath: "/root/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell" });
const pg = await b.newPage(); let ok = 0, n = 0;
for (const [want, list] of [[false, blocked], [true, done]]) for (const h of list) {
  await pg.setContent(h); const got = await loginFinished(pg); n++; if (got === want) ok++; else console.log("BAD", h); }
console.log(`JS detection ${ok}/${n}`); await b.close();
