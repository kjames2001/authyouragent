"""Generate the two sequence diagrams on the home page (cloud/static/site/home.html).

Run: python tools/seq_diagrams.py  -> rewrites the two <svg> blocks in place.
Colours come from site.css (.seq rules), so the diagrams follow light/dark mode.
"""
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

HOME = Path(__file__).resolve().parent.parent / "cloud/static/site/home.html"
W = 860
LANES = [("Agent", 90, 96), ("Auth Your Agent", 330, 150), ("Your phone", 560, 112), ("Website", 770, 96)]
X = {n: x for n, x, _ in LANES}
TOP, ROW, PAD = 92, 54, 6          # first message y, row height, arrow gap to lane
CH = 7.6                           # rough width of one 14px character


def _text_x(cx, label):
    half = len(label) * CH / 2 + 8
    return max(half, min(W - half, cx))


def build(sid, title, rows):
    h = TOP + ROW * (len(rows) - 1) + 40
    out = [f'<svg viewBox="0 0 {W} {h}" role="img" aria-labelledby="{sid}"><title id="{sid}">{escape(title)}</title>',
           f'<defs><marker id="{sid}a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker>'
           f'<marker id="{sid}k" class="k" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z"/></marker></defs>']
    for name, x, bw in LANES:
        out.append(f'<g class="head"><rect x="{x - bw / 2}" y="10" width="{bw}" height="34" rx="8"/><text x="{x}" y="32">{escape(name)}</text></g>'
                   f'<line class="lane" x1="{x}" y1="44" x2="{x}" y2="{h - 6}"/>')
    for i, (a, b, label, kind) in enumerate(rows):
        y = TOP + ROW * i
        if kind == "note":
            x1, x2 = X[a] - 40, X[b] + 40
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
    ("Agent", "Website", "6. agent continues on the logged-in page; risky clicks ask your phone first", "note"),
    ("Agent", "Auth Your Agent", "7. done: vault signs you out", ""),
])

if __name__ == "__main__":
    s = HOME.read_text()
    new, n1 = re.subn(r'<svg viewBox="0 0 860 \d+" role="img" aria-labelledby="seqt">.*?</svg>', lambda m: APPROVAL, s, flags=re.S)
    new, n2 = re.subn(r'<svg viewBox="0 0 860 \d+" role="img" aria-labelledby="seqt2">.*?</svg>', lambda m: TAKEOVER, new, flags=re.S)
    if (n1, n2) != (1, 1):
        sys.exit(f"expected one of each diagram, found {n1}, {n2}")
    HOME.write_text(new)
    print("home.html: both diagrams rewritten")
