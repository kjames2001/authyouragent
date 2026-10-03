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
Smart also pauses on a site for an hour after the owner denies something
there, and once the hourly limit is used up.

Only the vault's own approval cards use modes. A site that asks the owner
itself (step-up, CIBA, sign-in) always asks: that is the site's rule, not ours.
"""
import json
import re
import time

MODES = ("ask", "smart", "off")
DEFAULT_LIMIT = 20          # smart: actions per agent, per site, per hour
MAX_LIMIT = 200
PAUSE_AFTER_DENY = 3600     # smart pauses on a site this long after a deny

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
    cols = {r[1] for r in c.execute("PRAGMA table_info(authnz_requests)")}
    if "details" not in cols:
        c.execute("ALTER TABLE authnz_requests ADD COLUMN details TEXT")


def get_modes(c, user_id, agent_id):
    """{"default": {...}, "sites": {site: {...}}} for the app."""
    out = {"default": {"mode": "ask", "hourly_limit": DEFAULT_LIMIT}, "sites": {}}
    for r in c.execute("SELECT site, mode, hourly_limit FROM approval_modes "
                       "WHERE user_id=? AND agent_id=?", (user_id, agent_id)):
        v = {"mode": r[1], "hourly_limit": r[2] or DEFAULT_LIMIT}
        if r[0] == "*":
            out["default"] = v
        else:
            out["sites"][r[0]] = v
    return out


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


def decide(c, user_id, agent_id, site, label, details=None, now=None):
    """(auto: bool, why: str). auto=True means approve without asking."""
    now = now or int(time.time())
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
    denied = c.execute("SELECT 1 FROM authnz_requests WHERE user_id=? AND agent_id=? AND site=? "
                       "AND kind='agent_approval' AND status='denied' AND created_at>? LIMIT 1",
                       (user_id, agent_id, site, now - PAUSE_AFTER_DENY)).fetchone()
    if denied:
        return False, f"Smart is paused on {site} for an hour after you denied something there"
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
    for k, n in (("label", 80), ("amount", 40), ("item", 120), ("order", 60), ("page", 200)):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = re.sub(r"\s+", " ", v).strip()[:n]
    # the vault falls back to the button's words for the item: not worth a line
    if out.get("item") and out.get("label") and words(out["item"]).lower() == words(out["label"]).lower():
        del out["item"]
    for k in ("card_fields", "password_fields"):
        if d.get(k) is True:
            out[k] = True
    return out


def details_json(d):
    return json.dumps(d, separators=(",", ":")) if d else None
