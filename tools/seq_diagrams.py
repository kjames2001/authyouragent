"""Generate the sequence diagrams on the home page (cloud/static/site/home.html).

Run: python tools/seq_diagrams.py  -> rewrites the <svg> blocks in place.
Colours come from site.css (.seq rules), so the diagrams follow light/dark mode.
"""
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HOME = Path(__file__).resolve().parent.parent / "cloud/static/site/home.html"
W = 860
LANES = [("Agent", 90, 96), ("Auth Your Agent", 330, 150), ("Your phone", 560, 112), ("Website", 770, 96)]
TOP, ROW, PAD = 92, 54, 6          # first message y, row height, arrow gap to lane
CH = 7.6                           # rough width of one 14px character


def _text_x(cx, label):
    half = len(label) * CH / 2 + 8
    return max(half, min(W - half, cx))


def build(sid, title, rows, lanes=LANES):
    X = {n: x for n, x, _ in lanes}
    h = TOP + ROW * (len(rows) - 1) + 40
    out = [f'<svg viewBox="0 0 {W} {h}" role="img" aria-labelledby="{sid}"><title id="{sid}">{escape(title)}</title>',
           f'<defs><marker id="{sid}a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker>'
           f'<marker id="{sid}k" class="k" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker></defs>']
    for name, x, bw in lanes:
        out.append(f'<g class="head"><rect x="{x - bw / 2}" y="10" width="{bw}" height="34" rx="8"/><text x="{x}" y="32">{escape(name)}</text></g>'
                   f'<line class="lane" x1="{x}" y1="44" x2="{x}" y2="{h - 6}"/>')
    for i, (a, b, label, kind) in enumerate(rows):
        y = TOP + ROW * i
        if kind == "note":
            x1, x2 = X[a] - 40, X[b] + 40
            need = len(label) * CH + 28
            if x2 - x1 < need:
                c = (x1 + x2) / 2
                x1, x2 = c - need / 2, c + need / 2
            out.append(f'<rect class="note" x="{x1}" y="{y - 22}" width="{x2 - x1}" height="34" rx="8"/>'
                       f'<text class="lbl" x="{(x1 + x2) / 2}" y="{y}" text-anchor="middle">{escape(label)}</text>')
            continue
        xa, xb = X[a], X[b]
        d = 1 if xb > xa else -1
        x1, x2 = xa + d * PAD, xb - d * PAD
        cls = "msg key" if kind == "key" else "msg"
        mk = f"{sid}k" if kind == "key" else f"{sid}a"
        tx = _text_x((x1 + x2) / 2, label)
        lcls = "lbl key" if kind == "key" else "lbl"
        bw = len(label) * CH + 12
        out.append(f'<line class="{cls}" x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" marker-end="url(#{mk})"/>'
                   f'<rect class="mask" x="{tx - bw / 2:.1f}" y="{y - 27}" width="{bw:.1f}" height="20"/>'
                   f'<text class="{lcls}" x="{tx}" y="{y - 11}" text-anchor="middle">{escape(label)}</text>')
    out.append("</svg>")
    return "".join(out)


APPROVAL = build("seqt",
    "Sequence: an agent asks for access, you approve on your phone, the agent calls the site with a short-lived pass, "
    "the site checks it, and sensitive actions ask your phone again.", [
    ("Agent", "Auth Your Agent", "1. asks for access: site + permissions", ""),
    ("Auth Your Agent", "Your phone", "2. approval request", ""),
    ("Your phone", "Auth Your Agent", "approved with your fingerprint", "key"),
    ("Auth Your Agent", "Agent", "3. short-lived pass (10 min, this site only)", ""),
    ("Agent", "Website", "4. request + pass + key signature", ""),
    ("Website", "Auth Your Agent", "checks pass, key, revocation", ""),
    ("Auth Your Agent", "Website", "valid: agent, person, permissions", ""),
    ("Website", "Agent", "sensitive action? 403 step-up required", ""),
    ("Agent", "Auth Your Agent", "5. asks again for this one action", ""),
    ("Auth Your Agent", "Your phone", "approval request", ""),
    ("Your phone", "Auth Your Agent", "approved (usable once, 60 s)", "key"),
    ("Auth Your Agent", "Agent", "one-time approval token", ""),
    ("Agent", "Website", "6. retries with it: action done", ""),
])

TAKEOVER = build("seqt2",
    "Take over sequence: the agent is stuck at a login, asks you to take over, you drive its browser from your phone, "
    "sign in, and hand it back. When the task is done, the vault signs you out and destroys the browser profile.", [
    ("Agent", "Website", "1. agent reaches a login, CAPTCHA or 2FA it can't pass", ""),
    ("Agent", "Auth Your Agent", "2. asks you to take over", ""),
    ("Auth Your Agent", "Your phone", "3. notification + live view of its browser", ""),
    ("Your phone", "Auth Your Agent", "you open it and take control", "key"),
    ("Your phone", "Website", "4. you type and tap on the live page", ""),
    ("Website", "Your phone", "site sees a normal human sign-in", ""),
    ("Your phone", "Agent", "5. you finish: browser handed back automatically", ""),
    ("Agent", "Website", "6. agent continues on the logged-in page; clicks follow your approval mode", "note"),
    ("Your phone", "Agent", "offer: save this sign-in to your password manager", ""),
    ("Agent", "Auth Your Agent", "7. done: vault signs you out", ""),
])

SAVED = build("seqt3",
    "Saved sign-in sequence: the agent asks the vault to fill a saved password or code by item name. The vault checks "
    "the page, reads the item from your Bitwarden or Vaultwarden, types it into the field, and tells the agent only "
    "that it was filled.", [
    ("Agent", "Website", "1. agent reaches a sign-in page", ""),
    ("Agent", "Vault", "2. list_secrets: item names + sites, no values", ""),
    ("Agent", "Vault", "3. fill_secret: item name + field", ""),
    ("Vault", "Vault", "checks: saved address, top frame, field kind", "note"),
    ("Vault", "Bitwarden / Vaultwarden", "4. sync, decrypt on your machine", ""),
    ("Vault", "Website", "5. types the password or code into the field", "key"),
    ("Vault", "Agent", "6. \u201cfilled\u201d \u2014 never the value", ""),
    ("Vault", "Bitwarden / Vaultwarden", "your phone is told: saved sign-in used on this site", "note"),
    ("Agent", "Website", "7. agent submits; sign-ins it can't fill go to take over", "note"),
], lanes=[("Agent", 90, 96), ("Vault", 330, 150), ("Bitwarden / Vaultwarden", 560, 196), ("Website", 770, 96)])

PLAN = build("seqt4",
    "Scheduled plan sequence: when a task is set up, the agent submits a plan with the exact steps and text. You "
    "approve it once with your passkey. Later, while you are away, each click that matches a step exactly goes "
    "through without asking; anything else, and every payment, still asks your phone.", [
    ("Agent", "Auth Your Agent", "1. submit_plan: when, how many runs, each step's exact text", ""),
    ("Auth Your Agent", "Your phone", "2. one card: every step, the full text, the runs", ""),
    ("Your phone", "Auth Your Agent", "approved once, with your passkey", "key"),
    ("Agent", "Website", "later, while you are away: a run starts", "note"),
    ("Agent", "Vault", "3. click \u201cPost\u201d", ""),
    ("Vault", "Auth Your Agent", "page, button, hash of the text it sends", ""),
    ("Auth Your Agent", "Vault", "matches a step exactly: go", "key"),
    ("Vault", "Website", "4. clicks; summary to your phone at the end", ""),
    ("Agent", "Website", "a changed word, another page, a payment: asks your phone", "note"),
], lanes=[("Agent", 90, 96), ("Vault", 270, 96), ("Auth Your Agent", 470, 150), ("Your phone", 640, 112), ("Website", 790, 96)])

DIAGRAMS = {"seqt": APPROVAL, "seqt2": TAKEOVER, "seqt3": SAVED, "seqt4": PLAN}

if __name__ == "__main__":
    s = HOME.read_text()
    for sid, svg in DIAGRAMS.items():
        s, n = re.subn(rf'<svg viewBox="0 0 860 \d+" role="img" aria-labelledby="{sid}">.*?</svg>', lambda m: svg, s, flags=re.S)
        if n != 1:
            sys.exit(f"expected one {sid} diagram in home.html, found {n}")
    HOME.write_text(s)
    print(f"home.html: {len(DIAGRAMS)} diagrams rewritten")
