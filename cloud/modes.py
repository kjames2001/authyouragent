"""Approval modes for vault clicks (agent_approval cards). Rules only: no
model, no AI judge, by design. Every decision can be explained from the
facts below, and a page cannot argue its way past them.

Modes, set by the owner in the app, per agent, with per-site exceptions:
  ask    every committing action asks the owner's phone (default)
  smart  low-risk, reversible actions go through without asking, up to a
         per-site hourly limit; everything else asks
  off    nothing asks on that site, except account and security changes.
         Only per site, never for all sites.

Always asks, in every mode except as noted:
  money       an amount on the form, card fields, or pay/buy/order wording
  delete      delete, remove, cancel, close account ...
  publish     post, send, comment, reply, share, invite ... (acts as the owner)
  security    password, email, two-factor, keys, authorize/grant (asks even
              in off)
  unknown     the vault could not read the action clearly
Smart also pauses for an hour after the owner denies something, and once
the hourly limit is used up. The owner chooses what a deny pauses (per agent,
in the app): the whole domain (default: a deny on shop.example.com also pauses
example.com and its other subdomains) or only the exact address it happened on
(the host, e.g. shop.example.com).

Only the vault's own approval cards use modes. A site that asks the owner
itself (step-up, CIBA, sign-in) always asks: that is the site's rule, not ours.
"""
import json
import re
import time
import unicodedata

MODES = ("ask", "smart", "off")
DEFAULT_LIMIT = 20          # smart: actions per agent, per site, per hour
MAX_LIMIT = 200
PAUSE_AFTER_DENY = 3600     # smart pauses on a site this long after a deny
PAUSE_SCOPES = ("domain", "host")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")

MONEY = re.compile(
    r"\b(pay|payment|purchase|buy|order|checkout|check out|subscribe|upgrade|donate|"
    r"transfer|withdraw|tip|book|reserve|rent|bid|top ?up|renew)\b", re.I)
DELETE = re.compile(
    r"\b(delete|remove|erase|destroy|discard|wipe|cancel|close (account|issue|pull request)|"
    r"deactivate|unsubscribe|leave|block|revoke|reset)\b", re.I)
PUBLISH = re.compile(
    r"\b(post|publish|send|share|comment|reply|tweet|invite|message|submit|review|rate|"
    r"vote|like|follow|report|make public|go live|announce|merge|deploy|release)\b", re.I)
SECURITY = re.compile(
    r"\b(password|passcode|e-?mail|two.?factor|2fa|mfa|security|recovery|passkey|"
    r"ssh key|api key|token|authori[sz]e|grant|allow|permission|access|accept|approve|"
    r"add (member|user|collaborator|admin|owner)|transfer ownership|payment method|card|"
    r"billing|address)\b", re.I)
# What smart may let through: changes the owner can undo in a click.
LOW_RISK = re.compile(
    r"^(save|save changes|save draft|save for later|save settings|save preferences|update|"
    r"update settings|update preferences|apply|apply filters?|filter|sort|refresh|rename|"
    r"archive|unarchive|restore|reopen|undo|star|unstar|pin|unpin|bookmark|"
    r"mark (as )?(read|unread|done|complete)|"
    r"add to (cart|basket|bag|wish ?list|list|favou?rites|collection|reading list|watch ?list)|"
    r"(show|load) more|next page|previous page|done|ok)$", re.I)
CURRENCY = re.compile(r"([$€£¥₹]|\b(usd|eur|gbp|bwp|zar|p)\b)\s?\d", re.I)


HIDDEN = ("Cc", "Cf", "Co", "Cs", "Cn")   # control, format (bidi, zero-width), private, unassigned
BREAKS = ("Zl", "Zp")                      # Unicode line/paragraph separators


def has_hidden(s):
    """True if the text holds a character the owner cannot see as written:
    control or format characters (right-to-left overrides, zero-width
    joiners), private-use or unassigned code points, or Unicode line breaks."""
    return any(unicodedata.category(ch) in HIDDEN + BREAKS for ch in s)


def plain(s, newlines=False):
    """Text as the owner will read it: hidden characters removed, Unicode line
    breaks turned into spaces (or into \\n when newlines=True)."""
    out = []
    for ch in str(s or ""):
        cat = unicodedata.category(ch)
        if ch == "\n" and newlines:
            out.append(ch)
        elif cat in BREAKS or ch in "\t\r\x0b\x0c\x85":
            out.append("\n" if newlines else " ")
        elif cat == "Cc":                      # other control characters: a space, so words stay apart
            out.append(" ")
        elif cat not in HIDDEN:
            out.append(ch)
    return "".join(out)


def words(label):
    """The action's wording as the vault read it ("save_changes" from older
    vaults, or "Save changes")."""
    return re.sub(r"\s+", " ", re.sub(r"[_\-]+", " ", str(label or ""))).strip()


def classify(label, details=None):
    """(category, reason). Categories: money, delete, publish, security,
    unknown, low."""
    d = details or {}
    w = words(d.get("label") or label)
    if not w or w.lower() in ("action", "submit form", "submit"):
        return "unknown", "the action has no clear wording"
    if d.get("card_fields"):
        return "money", "the form asks for card details"
    if d.get("amount") or CURRENCY.search(w):
        return "money", f"an amount is shown ({d.get('amount') or w})"
    if MONEY.search(w):
        return "money", f"'{w}' spends money"
    if SECURITY.search(w) or d.get("password_fields"):
        return "security", f"'{w}' changes account or security settings"
    if DELETE.search(w):
        return "delete", f"'{w}' deletes or cancels something"
    if PUBLISH.search(w):
        return "publish", f"'{w}' posts or sends as you"
    if LOW_RISK.match(w):
        return "low", f"'{w}' can be undone"
    return "unknown", f"'{w}' is not on the low-risk list"


# ------------------------------------------------------------------ storage

def migrate(c):
    c.execute("""CREATE TABLE IF NOT EXISTS approval_modes(
      user_id TEXT NOT NULL, agent_id TEXT NOT NULL, site TEXT NOT NULL,
      mode TEXT NOT NULL, hourly_limit INTEGER, updated_at INTEGER,
      PRIMARY KEY(user_id, agent_id, site))""")
    if "pause_scope" not in {r[1] for r in c.execute("PRAGMA table_info(approval_modes)")}:
        c.execute("ALTER TABLE approval_modes ADD COLUMN pause_scope TEXT")
    cols = {r[1] for r in c.execute("PRAGMA table_info(authnz_requests)")}
    if "details" not in cols:
        c.execute("ALTER TABLE authnz_requests ADD COLUMN details TEXT")


def get_modes(c, user_id, agent_id):
    """{"default": {...}, "sites": {site: {...}}} for the app."""
    out = {"default": {"mode": "ask", "hourly_limit": DEFAULT_LIMIT}, "sites": {},
           "pause_scope": "domain"}
    for r in c.execute("SELECT site, mode, hourly_limit, pause_scope FROM approval_modes "
                       "WHERE user_id=? AND agent_id=?", (user_id, agent_id)):
        v = {"mode": r[1], "hourly_limit": r[2] or DEFAULT_LIMIT}
        if r[0] == "*":
            out["default"] = v
            out["pause_scope"] = r[3] if r[3] in PAUSE_SCOPES else "domain"
        else:
            out["sites"][r[0]] = v
    return out


def pause_scope(c, user_id, agent_id):
    r = c.execute("SELECT pause_scope FROM approval_modes WHERE user_id=? AND agent_id=? AND site='*'",
                  (user_id, agent_id)).fetchone()
    return r[0] if r and r[0] in PAUSE_SCOPES else "domain"


def set_pause_scope(c, user_id, agent_id, scope):
    """What a deny pauses: "domain" (the whole domain) or "host" (only the
    exact address). Kept on the agent's all-sites row; creating that row
    keeps the mode at Ask."""
    if scope not in PAUSE_SCOPES:
        raise ValueError("the pause covers the domain or the exact address")
    c.execute("INSERT INTO approval_modes(user_id, agent_id, site, mode, hourly_limit, updated_at, pause_scope) "
              "VALUES(?,?,'*','ask',?,?,?) ON CONFLICT(user_id, agent_id, site) DO UPDATE SET "
              "pause_scope=excluded.pause_scope, updated_at=excluded.updated_at",
              (user_id, agent_id, DEFAULT_LIMIT, int(time.time()), scope))


def set_mode(c, user_id, agent_id, site, mode, hourly_limit=None):
    """site "*" = all sites. mode None removes a site exception."""
    if site == "*" and mode == "off":
        raise ValueError("Off can only be set for one site at a time")
    if mode is None:
        if site == "*":
            raise ValueError("choose a mode for all sites")
        c.execute("DELETE FROM approval_modes WHERE user_id=? AND agent_id=? AND site=?",
                  (user_id, agent_id, site))
        return
    if mode not in MODES:
        raise ValueError("mode must be ask, smart or off")
    lim = int(hourly_limit or DEFAULT_LIMIT)
    if not 1 <= lim <= MAX_LIMIT:
        raise ValueError(f"the hourly limit must be 1 to {MAX_LIMIT}")
    c.execute("INSERT INTO approval_modes(user_id, agent_id, site, mode, hourly_limit, updated_at) "
              "VALUES(?,?,?,?,?,?) ON CONFLICT(user_id, agent_id, site) DO UPDATE SET "
              "mode=excluded.mode, hourly_limit=excluded.hourly_limit, updated_at=excluded.updated_at",
              (user_id, agent_id, site, mode, lim, int(time.time())))


def _site_rule(c, user_id, agent_id, site):
    """The rule for this site: its own exception, else a parent domain's
    (shop.example.com uses example.com's), else the agent's default."""
    parts = site.split(".")
    for i in range(len(parts) - 1):
        r = c.execute("SELECT mode, hourly_limit FROM approval_modes WHERE user_id=? AND agent_id=? "
                      "AND site=?", (user_id, agent_id, ".".join(parts[i:]))).fetchone()
        if r:
            return r[0], r[1] or DEFAULT_LIMIT, ".".join(parts[i:])
    r = c.execute("SELECT mode, hourly_limit FROM approval_modes WHERE user_id=? AND agent_id=? "
                  "AND site='*'", (user_id, agent_id)).fetchone()
    return (r[0], r[1] or DEFAULT_LIMIT, "*") if r else ("ask", DEFAULT_LIMIT, "*")


def site_of(host):
    """The site a host belongs to: the last two labels, or an IP as is
    (the vault's rule, broker._site)."""
    host = (host or "").lower()
    if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
        return host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def sends_elsewhere(site, details):
    """The host a click's form posts to when that is another site than the
    page's, else "". Vaults before 0.3.27 do not send it: ""."""
    th = (details or {}).get("target_host") or ""
    return th if th and site_of(th) != site_of(site) else ""


def decide(c, user_id, agent_id, site, label, details=None, now=None):
    """(auto: bool, why: str). auto=True means approve without asking.
    `site` is the domain; details["host"] (vault 0.3.20+) the exact address."""
    now = now or int(time.time())
    host = (details or {}).get("host")
    mode, limit, where = _site_rule(c, user_id, agent_id, site)
    cat, reason = classify(label, details)
    scope = "all sites" if where == "*" else where
    if mode == "ask":
        return False, f"Ask mode ({scope})"
    if mode == "off":
        if cat == "security":
            return False, f"Off ({scope}), but {reason}: always asks"
        return True, f"Off mode on {scope}: {reason}" if cat == "low" else f"Off mode on {scope}"
    # smart
    if cat != "low":
        return False, f"Smart ({scope}): {reason}, so it asks"
    off = sends_elsewhere(site, details)
    if off:
        return False, f"Smart ({scope}): the form sends to {off}, another site, so it asks"
    q = ("SELECT 1 FROM authnz_requests WHERE user_id=? AND agent_id=? AND site=? "
         "AND kind='agent_approval' AND status='denied' AND created_at>?")
    args = [user_id, agent_id, site, now - PAUSE_AFTER_DENY]
    paused_on = site
    # exact address: only denies on this host count. A vault too old to send
    # the host pauses the whole domain, the safe side.
    if host and pause_scope(c, user_id, agent_id) == "host":
        q += " AND json_extract(details, '$.host')=?"
        args.append(host)
        paused_on = host
    if c.execute(q + " LIMIT 1", args).fetchone():
        return False, f"Smart is paused on {paused_on} for an hour after you denied something there"
    used = c.execute("SELECT COUNT(*) FROM authnz_requests WHERE user_id=? AND agent_id=? AND site=? "
                     "AND kind='agent_approval' AND status='approved' AND approved_via='smart' "
                     "AND created_at>?", (user_id, agent_id, site, now - 3600)).fetchone()[0]
    if used >= limit:
        return False, f"Smart limit reached on {site} ({limit} an hour)"
    return True, f"Smart ({scope}): {reason}"


def clean_details(d):
    """What the vault read from the page, trimmed to what the card shows."""
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, n in (("label", 80), ("amount", 40), ("item", 120), ("order", 60), ("page", 200), ("repeat", 240)):
        v = d.get(k)
        if isinstance(v, str):
            v = re.sub(r"\s+", " ", plain(v)).strip()[:n]
            if v:
                out[k] = v
    # the vault falls back to the button's words for the item: not worth a line
    if out.get("item") and out.get("label") and words(out["item"]).lower() == words(out["label"]).lower():
        del out["item"]
    h = d.get("host")
    if isinstance(h, str) and HOST_RE.match(h.strip().lower()) and len(h) <= 253:
        out["host"] = h.strip().lower()
    # where the form posts (vault 0.3.27+); shown on the card when it is
    # another site than the page
    th = d.get("target_host")
    if isinstance(th, str) and HOST_RE.match(th.strip().lower()) and len(th) <= 253:
        out["target_host"] = th.strip().lower()
    for k in ("card_fields", "password_fields"):
        if d.get(k) is True:
            out[k] = True
    # plans (vault 0.3.25+): the page's path and digests of the form's texts,
    # compared exactly with a pre-approved step; never shown on the card
    pth = d.get("path")
    if isinstance(pth, str) and re.fullmatch(r"/[\x21-\x7e]{0,300}", pth):
        out["path"] = pth
    tds = d.get("text_digests")
    if isinstance(tds, list) and len(tds) <= 8 and all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in tds):
        out["text_digests"] = sorted(tds)
    return out


def details_json(d):
    return json.dumps(d, separators=(",", ":")) if d else None
