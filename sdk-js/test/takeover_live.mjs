// Live check of the JS takeover helper against a dev cloud.
// env: CLOUD, NODE_PATH (ws + playwright-core), CHROME, PHONE (python sim_phone.py path), PY
import { AgentClient, keygen } from "../src/index.js";
import { takeover, loginFinished } from "../src/takeover.js";
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";
import { writeFileSync, existsSync, unlinkSync } from "node:fs";

const CLOUD = process.env.CLOUD, PW = "hunter2hunter";
let pass = 0, total = 0;
const check = (n, ok, extra = "") => { total++; if (ok) pass++; console.log(ok ? "PASS" : "FAIL", n, ok ? "" : extra); };
const H = { "content-type": "application/json", origin: CLOUD };
const email = `jstk+${Date.now()}@example.test`;
let r = await fetch(CLOUD + "/api/users", { method: "POST", headers: H, body: JSON.stringify({ email, password: PW, display_name: "J" }) });
const cookie = r.headers.get("set-cookie").split(";")[0];
const { privateKeyPem, jwk } = await keygen();
r = await fetch(CLOUD + "/api/agents", { method: "POST", headers: { ...H, cookie }, body: JSON.stringify({ name: "JS helper", jwk }) });
const agentId = (await r.json()).id;
const agent = new AgentClient({ agentId, privateKeyPem, baseUrl: CLOUD });

const PAGE = `<!doctype html><body style="font:18px sans-serif;padding:20px"><h2>Sign in</h2>
<p><input id=u style="font-size:18px;width:90vw"></p><p><input id=p type=password style="font-size:18px;width:90vw"></p>
<p><button id=go onclick="if(p.value==='s3cret')document.body.innerHTML='<h2>Welcome back</h2>'">Sign in</button></p></body>`;
const b = await chromium.launch({ executablePath: process.env.CHROME });
const ctx = await b.newContext({ viewport: { width: 800, height: 600 } });
const page = await ctx.newPage();
await page.route("https://shop.example/**", (rt) => rt.fulfill({ status: 200, contentType: "text/html", body: PAGE }));
await page.goto("https://shop.example/login");

const steps = "/root/.hermes/cache/scratch/js_steps.json";
if (existsSync(steps)) unlinkSync(steps);
const ph = spawn(process.env.PY, [process.env.PHONE, CLOUD, email, PW, steps]);
let phOut = ""; ph.stdout.on("data", (d) => (phOut += d)); ph.stderr.on("data", (d) => (phOut += d));
const phDone = new Promise((r) => ph.on("close", r));

let live = false;
const t = takeover(agent, page, "Please sign in (JS)", { check: loginFinished, insecure: true,
  onLive: async () => {
    live = true;
    await new Promise((r) => setTimeout(r, 800));
    const c = async (s) => page.$eval(s, (e) => { const b = e.getBoundingClientRect(); return [b.x + b.width / 2, b.y + b.height / 2]; });
    const [u, p, g] = [await c("#u"), await c("#p"), await c("#go")];
    writeFileSync(steps, JSON.stringify([["tap", ...u], ["type", "ada"], ["tap", ...p], ["type", "s3cret"], ["tap", ...g]]));
  } });
const result = await Promise.race([t, new Promise((r) => setTimeout(() => r("timeout"), 90000))]);
await Promise.race([phDone, new Promise((r) => setTimeout(r, 20000))]);
check("phone took over", live);
check("typing on the page reached the agent and Sign in handed back automatically", result === "done", `${result} ${phOut.slice(-300)}`);
check("agent page signed in", (await page.innerText("body")).includes("Welcome back"));
check("page back at its own size", JSON.stringify(page.viewportSize()) === '{"width":800,"height":600}');
await b.close();
console.log(`RESULT: ${pass}/${total} JS takeover checks passed`);
process.exit(pass === total ? 0 : 1);
