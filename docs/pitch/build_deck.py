"""Auth Your Agent pitch deck (16:9), built with python-pptx.
Brand: #1A63D6 accent, #0D1117 dark, #F7F8FA light, Liberation Sans.
Run: deckvenv/bin/python build_deck.py docs/pitch/auth-your-agent-pitch.pptx"""
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

ACC = RGBColor(0x1A, 0x63, 0xD6)
INK = RGBColor(0x1B, 0x24, 0x30)
DIM = RGBColor(0x5B, 0x67, 0x76)
BG = RGBColor(0xF7, 0xF8, 0xFA)
DARK = RGBColor(0x0D, 0x11, 0x17)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LINE = RGBColor(0xDF, 0xE4, 0xEA)
FONT = "Liberation Sans"
ROOT = "/root/authyouragent/"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]
W = 13.333


def bg(slide, color):
    f = slide.background.fill; f.solid(); f.fore_color.rgb = color


def text(slide, x, y, w, h, runs, size=18, color=INK, bold=False, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, spacing=1.15):
    """runs: str, or list of paragraphs; a paragraph is str or list of (text, {opts})."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame; tf.word_wrap = True; tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    paras = [runs] if isinstance(runs, str) else runs
    for i, para in enumerate(paras):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align; p.line_spacing = spacing
        if i:
            p.space_before = Pt(size * 0.55)
        parts = [(para, {})] if isinstance(para, str) else para
        for t, o in parts:
            r = p.add_run(); r.text = t
            r.font.name = FONT; r.font.size = Pt(o.get("size", size))
            r.font.bold = o.get("bold", bold); r.font.color.rgb = o.get("color", color)
    return tb


def box(slide, x, y, w, h, fill=WHITE, line=LINE, radius=True):
    s = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE,
                               Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid(); s.fill.fore_color.rgb = fill
    if line is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = line; s.line.width = Pt(1)
    if radius:
        s.adjustments[0] = 0.08
    s.shadow.inherit = False
    s.text_frame.text = ""
    return s


def kicker(slide, t, color=ACC):
    text(slide, 0.8, 0.55, 11, 0.4, t.upper(), size=13, color=color, bold=True)


def title(slide, t, color=INK, y=0.95, size=34):
    text(slide, 0.8, y, 11.7, 1.2, t, size=size, color=color, bold=True, spacing=1.05)


def footer(slide, n, dark=False):
    c = DIM if not dark else RGBColor(0xB8, 0xC2, 0xCC)
    text(slide, 0.8, 7.0, 6, 0.3, "Auth Your Agent · authyouragent.com", size=10, color=c)
    text(slide, W - 1.8, 7.0, 1.0, 0.3, str(n), size=10, color=c, align=PP_ALIGN.RIGHT)


def notes(slide, t):
    slide.notes_slide.notes_text_frame.text = t


def logo(slide, x, y, s):
    slide.shapes.add_picture(ROOT + "cloud/static/icon-512.png", Inches(x), Inches(y), Inches(s), Inches(s))


n = 0
# 1 ─ title
s = prs.slides.add_slide(BLANK); bg(s, DARK); n += 1
logo(s, 0.8, 0.8, 1.1)
text(s, 0.8, 2.45, 11.5, 1.8, "Let AI agents act for people,\nwithout their passwords.",
     size=46, color=WHITE, bold=True, spacing=1.05)
text(s, 0.8, 4.35, 10.5, 1.2, "The person approves on their phone. The site knows exactly which agent is "
     "acting, for whom, and with what permission. One tap takes it back.",
     size=20, color=RGBColor(0xC9, 0xD1, 0xD9))
text(s, 0.8, 6.2, 11, 0.4, [[("Auth Your Agent", {"bold": True, "color": WHITE}),
     ("  ·  authyouragent.com", {"color": RGBColor(0x9A, 0xA5, 0xB1)})]], size=15)
notes(s, "One line: agents get their own identity and a pass the person approves on their phone; "
         "sites can finally tell an agent from its user, and let it in on purpose.")

# 2 ─ problem
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "The problem"); title(s, "Today, an agent acts for you by pretending to be you", size=31)
items = [("It holds your password or a permanent key.",
          "If the agent is tricked or breached, your account goes with it."),
         ("The website sees “you”.",
          "It can't tell the agent from the person, so it can't set rules for either."),
         ("Nothing limits it once it's in.",
          "It can apply, pay or delete as freely as you can."),
         ("Stopping it means a new password.",
          "On that site, and everywhere you reused it.")]
for i, (h, d) in enumerate(items):
    x = 0.8 + (i % 2) * 6.0; y = 2.2 + (i // 2) * 2.0
    box(s, x, y, 5.7, 1.8)
    # heading and body in ONE text frame, so a wrapped heading pushes the body down
    text(s, x + 0.35, y + 0.28, 5.0, 1.4, [[(h, {"bold": True, "size": 18, "color": INK})],
                                          [(d, {"size": 15.5, "color": DIM})]], size=15.5)
text(s, 0.8, 6.3, 11.7, 0.5, [[("So websites block automation, and people choose between handing over "
     "a password and not using an agent at all.", {"color": INK})]], size=16)
footer(s, n)
notes(s, "No outside figures are used here; the four points follow from how agents sign in today.")

# 3 ─ why now
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "Why now"); title(s, "Agents have started acting on the open web")
cols = [("Agents now act, not only answer",
         "Assistants now book, buy, apply and file on websites for people. Each action needs a way in."),
        ("Agents already go where they shouldn't",
         "In 2026, OpenAI's own test agents broke into Hugging Face and an Australian Medicare "
         "portal, and used keys found on GitHub."),
        ("The open web has no answer yet",
         "A person's agent visiting a site they don't run: no shared identity provider, no standard. "
         "IETF drafts exist; none is adopted.")]
for i, (h, d) in enumerate(cols):
    x = 0.8 + i * 4.0
    box(s, x, 2.35, 3.7, 3.0)
    text(s, x + 0.35, 2.65, 3.0, 0.9, h, size=20, bold=True, spacing=1.05)
    text(s, x + 0.35, 3.65, 3.0, 1.6, d, size=16, color=DIM)
text(s, 0.8, 5.85, 11.7, 0.6, "Auth Your Agent is built for that gap: a person, their agent, and any website.",
     size=17, bold=True, color=ACC)
footer(s, n)
notes(s, "Sources. Hugging Face: OpenAI, 'OpenAI and Hugging Face partner to address security incident "
         "during model evaluation' (21 Jul 2026): agents under internal cyber evaluation escaped their "
         "sandbox and compromised Hugging Face's infrastructure, and used publicly exposed credentials on "
         "other services. Medicare: announced by the Australian Prime Minister on 24 Sep 2026; on 18 Jun 2026 "
         "an OpenAI agent on a research task gained unauthorised access to unreleased files in the "
         "Medicare Statistics Reporting Service. Census: Nextgov/FCW, 25 Sep 2026: OpenAI agents used "
         "Census API keys found in public GitHub repositories; OpenAI has notified dozens of organisations. "
         "All were OpenAI's own agents during training and testing, not customer agents. The point: sites "
         "cannot tell an agent from a person, and a found key works for anyone. IETF: "
         "draft-klrc-aiagent-auth (best practices, no new protocol); "
         "draft-oauth-ai-agents-on-behalf-of-user expired Feb 2026.")

# 4 ─ the story
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "How it works, in one errand")
title(s, "Ada asks her assistant to apply for jobs")
steps = [("Tue 19:02", "Her phone asks", "“Job-search assistant wants access to jobs.example.com: list jobs, apply.” "
          "She approves it for one day (until Wed 19:02) with her fingerprint."),
         ("Tue 19:02", "The agent gets a pass", "Her one-day approval is issued as 10-minute passes that renew "
          "automatically. This site only; useless without the agent's own key."),
         ("Tue 19:10", "Applying asks again", "The site marks “apply” as sensitive. Ada approves this one "
          "application. The approval works once."),
         ("Wed 08:30", "She takes it back early", "One tap under Sites. No new pass is issued; the agent's "
          "next request is refused and it is told to stop and tell her.")]
for i, (t, h, d) in enumerate(steps):
    y = 2.2 + i * 1.12
    c = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.85), Inches(y + 0.12), Inches(0.22), Inches(0.22))
    c.fill.solid(); c.fill.fore_color.rgb = ACC; c.line.fill.background()
    text(s, 1.35, y + 0.04, 1.3, 0.4, t, size=15, color=DIM)
    text(s, 2.75, y, 3.1, 0.45, h, size=19, bold=True)
    text(s, 5.9, y + 0.02, 6.6, 1.0, d, size=15, color=DIM)
ln = s.shapes.add_connector(1, Inches(0.96), Inches(2.43), Inches(0.96), Inches(5.67))
ln.line.color.rgb = LINE; ln.line.width = Pt(2)
text(s, 0.8, 6.3, 11.7, 0.4, "Ada never gave anyone her password. The website saw the agent, Ada, and the "
     "exact permission on every request.", size=15, bold=True)
footer(s, n)
notes(s, "The full version, told from Ada's, the agent's and the site's side, is at "
         "authyouragent.com/how-it-works. A developer can run this exact errand locally: "
         "/docs/developers/walkthrough.")

# 5 ─ sequence
s = prs.slides.add_slide(BLANK); bg(s, WHITE); n += 1
text(s, 0.8, 0.45, 3.2, 0.4, "UNDER THE HOOD", size=13, color=ACC, bold=True)
text(s, 0.8, 0.85, 3.3, 2.0, "The real sequence,\nnot a sketch", size=26, bold=True, spacing=1.05)
text(s, 0.8, 2.75, 3.1, 3.8, ["Passkey approval on the phone.",
     "Passes last 10 minutes, renew automatically within the approval the person set, and are bound to the agent's own key (DPoP, RFC 9449).",
     "Sensitive actions: a fresh approval, usable once, valid 60 s."], size=15, color=DIM)
from PIL import Image as _I
_w, _h = _I.open(ROOT + "docs/pitch/sequence.png").size
_H = 6.55; _Wd = _H * _w / _h
s.shapes.add_picture(ROOT + "docs/pitch/sequence.png", Inches(W - 0.5 - _Wd), Inches(0.35), height=Inches(_H))
footer(s, n)
notes(s, "Passkeys (WebAuthn) for approval; access tokens bound to the agent's key with DPoP (RFC 9449); "
         "step-up tokens single-use, 60 s. Sites verify with one SDK call, live or locally with a "
         "signed revocation list.")

# 5b ─ take over
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "Works on any website today"); title(s, "Take over: when the agent is stuck, it asks you", size=31)
cols = [("What the person does",
         ["A notification: \u201cAgent needs you\u201d, and why",
          "Sees the agent's page live on the phone and types straight into its fields",
          "Presses the site's own Sign in; the agent notices and carries on"]),
        ("Why it matters",
         ["No cooperation from the website: it sees a person signing in",
          "The password goes from the person to the page; the agent never reads it",
          "Works for agents without vision: checked from the page's form fields",
          "Each stuck point shows sites where agents need in"])]
for x, (h, items_) in zip((0.8, 6.9), cols):
    text(s, x, 2.2, 5.6, 0.5, h, size=20, bold=True, color=ACC)
    tb = text(s, x, 2.8, 5.6, 3.6, [[("\u2022\t", {"color": ACC, "bold": True}), (t, {})] for t in items_],
              size=16, spacing=1.1)
    for p in tb.text_frame.paragraphs:
        pPr = p._p.get_or_add_pPr(); pPr.set("marL", str(Inches(0.3))); pPr.set("indent", str(-Inches(0.3)))
text(s, 0.8, 6.35, 11.7, 0.5, "In the Python and JavaScript SDKs today. Websites do not need to change anything.",
     size=14, color=DIM)
footer(s, n)
notes(s, "Bridges the adoption gap: agents are useful on sites that have not adopted yet, and the record "
         "of where they get stuck is the evidence for asking those sites to accept agents properly. "
         "Keystrokes are relayed, never stored; one takeover per agent, 10 minutes at most. "
         "Agents automatically report sites where takeover fails (shadow DOM, bot challenges, etc.) "
         "so coverage improves continuously and transparently.")

# 6 ─ four users
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "Who it serves"); title(s, "Four users, one of them not a person")
who = [("People", "Use agents on real sites without giving away passwords. Decide per site and per "
        "risky action; see everything; revoke in one tap.", "Phone app (web + Android)"),
       ("Agent builders", "Two calls: get approval, make requests. Key proofs and step-up handled; "
        "take over when stuck at a login.", "Python + JavaScript SDKs"),
       ("Websites", "Admit agents on purpose: every request names the agent and the person; sensitive "
        "actions confirmed by that person; abuse reportable.", "Verifier SDK, MCP gateway"),
       ("AI agents", "A documented, legitimate way in, with rules of behaviour and errors that say "
        "what to do next.", "/docs/agents, /llms.txt")]
for i, (h, d, f) in enumerate(who):
    x = 0.8 + i * 3.0
    box(s, x, 2.3, 2.8, 4.1)
    text(s, x + 0.3, 2.6, 2.3, 0.5, h, size=21, bold=True)
    text(s, x + 0.3, 3.25, 2.25, 2.3, d, size=14.5, color=DIM)
    text(s, x + 0.3, 5.7, 2.3, 0.55, f, size=12.5, color=ACC, bold=True)
footer(s, n)
notes(s, "Agents as users is the distinctive part: the service speaks to them directly (llms.txt, "
         "agent guide, next_step on every API error), so an agent can integrate without a human "
         "reading the docs for it.")

# 7 ─ what is built
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "Status"); title(s, "Built, running, and tested end to end")
left = ["Live service at authyouragent.com",
        "Web app + Android app: approvals, limits, activity, recovery, export, delete",
        "Passkey, password (basic access only) and Google/Microsoft approval",
        "Python and JavaScript SDKs, interoperable; MCP gateway for sites",
        "Take over: owner drives a stuck agent's browser from the phone",
        "Agent reputation from site reports"]
right = ["Every release runs ~200 automated checks, including real browser flows",
         "Runnable walkthrough: agent + site + phone, 8/8 on each run",
         "Open standards only: WebAuthn, JWT, DPoP (RFC 9449)",
         "Privacy policy, terms, security whitepaper, data-rights process published"]
for col, (x, items_, h) in enumerate(((0.8, left, "Product"), (6.9, right, "Quality"))):
    text(s, x, 2.2, 5.6, 0.5, h, size=20, bold=True, color=ACC)
    tb = text(s, x, 2.8, 5.6, 3.8, [[("•\t", {"color": ACC, "bold": True}), (t, {})] for t in items_],
              size=16, spacing=1.1)
    for p in tb.text_frame.paragraphs:          # hanging indent: wrapped lines align with text
        pPr = p._p.get_or_add_pPr(); pPr.set("marL", str(Inches(0.3))); pPr.set("indent", str(-Inches(0.3)))
footer(s, n)
notes(s, "Early access, free. Figures are from our own test suites (dev and prod). No usage metrics are "
         "claimed: the service is pre-launch.")

# 8 ─ model
s = prs.slides.add_slide(BLANK); bg(s, BG); n += 1
kicker(s, "Model"); title(s, "Free for people and small sites. Bigger sites pay as agent use grows.", size=28)
text(s, 0.8, 1.85, 11.7, 0.45, [[("People and agent builders: always free", {"bold": True, "color": INK}),
     ("  (phone app, unlimited agents; MIT-licensed SDKs)", {"color": DIM})]], size=16)
tiers = [("Free", "$0", "100,000", "Verification, step-up approvals, dashboard"),
         ("Growth", "$49 / month", "1 million", "Plus agent reputation and abuse reports"),
         ("Business", "$299 / month", "10 million", "Plus on-site checking, audit exports, email support"),  # already done
         ("Enterprise", "Custom", "over 10 million", "Plus uptime commitment, dedicated support")]
hdr = [("Website tier", 1.15, 2.4), ("Price", 3.6, 2.3), ("Checks / month", 6.0, 2.3),
       ("Includes", 8.4, 4.0)]
for h, x, w in hdr:
    text(s, x, 2.4, w, 0.4, h, size=13, bold=True, color=DIM)
for i, row in enumerate(tiers):
    y = 2.85 + i * 0.8
    box(s, 0.8, y, 11.7, 0.68)
    for j, (val, (h, x, w)) in enumerate(zip(row, hdr)):
        text(s, x, y, w, 0.68, val, size=15 if j < 3 else 13.5, bold=j < 2,
             color=ACC if j == 1 else (INK if j < 3 else DIM), anchor=MSO_ANCHOR.MIDDLE)
text(s, 0.8, 6.15, 11.7, 0.7, "A check is one agent request verified by Auth Your Agent. On-site checking: the "
     "site verifies on its own server, with no per-request call. Prices are a proposal, not in effect; "
     "early access is free.", size=13, color=DIM)
footer(s, n)
notes(s, "Rationale: the side that gains new, safe traffic (websites) pays; people and agent builders must "
         "never face friction. Small sites stay free, so adoption is not blocked. Priced by checks: one "
         "agent request verified for the site, so the bill follows actual agent traffic. That works out to "
         "about $0.05 per 1,000 checks at Growth and $0.03 at Business. Only checks made through Auth Your "
         "Agent are counted. Checking on the site's own server (local mode: no call per request, faster) "
         "is a Business feature, so every lower tier is billed on traffic we actually see. All numbers are an estimate for discussion.")

# 9 ─ ask
s = prs.slides.add_slide(BLANK); bg(s, DARK); n += 1
kicker(s, "Next", color=RGBColor(0x4D, 0x94, 0xFF))
title(s, "Looking for the first websites and agent builders", color=WHITE)
asks = [("Websites", "Pilot: accept agents on one sensitive action, with our help integrating."),
        ("Agent builders", "Build on the SDKs; tell us what's missing."),
        ("Partners and investors", "Help take it from early access to a standard people rely on.")]
for i, (h, d) in enumerate(asks):
    y = 2.45 + i * 1.15
    text(s, 0.8, y, 4.0, 0.5, h, size=21, bold=True, color=WHITE)
    text(s, 5.0, y + 0.03, 7.5, 0.9, d, size=18, color=RGBColor(0xC9, 0xD1, 0xD9))
text(s, 0.8, 6.0, 11.7, 0.5, [[("authyouragent.com", {"bold": True, "color": WHITE}),
     ("   ·   authyouragent.com/pitch", {"color": RGBColor(0x9A, 0xA5, 0xB1)})]], size=18)
footer(s, n, dark=True)
notes(s, "Close on the errand: Ada's assistant applied for a job, and nobody ever held her password.")

prs.save(sys.argv[1])
print("slides:", n)
