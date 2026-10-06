"""Plans: the owner pre-approves a scheduled task's actions (rules only).

An agent that will run while its owner is away submits a plan: a title, a
time window and a list of steps (site, exact address, button wording, and
for posts the exact text). The owner approves the plan once, on their
phone, all of it or some steps. During the window an approval request from
the vault that matches a pre-approved step exactly goes through without a
card. Anything that does not match asks as usual.

A step the owner does not answer in time, or denies, is skipped; steps
chained to it ("after") are refused without a card; the other steps carry
on. Payments and security changes are never pre-approved.

No model judges anything here: matching is exact comparison.
"""
import hashlib
import json
import re
import secrets
import time
from typing import NoReturn

import modes

MAX_STEPS = 20
MAX_USES = 5
MAX_WINDOW = 24 * 3600          # a plan's window is at most a day
MAX_AHEAD = 30 * 86400          # and starts within 30 days
MAX_TEXT = 10000                # characters per text the agent submits
MAX_TEXTS = 4                   # text fields per step (a title and a body, say)
NEVER = ("money", "security")   # always ask, even inside a plan
STEP_ID = re.compile(r"^[a-z0-9_-]{1,24}$")
PATH_RE = re.compile(r"^/[\x21-\x7e]{0,300}$")   # path and query (?id=1); a trailing * is a prefix


def norm_text(s):
    """The text as compared: hidden characters removed, line ends unified,
    each line's trailing spaces, blank lines (rich editors put one between
    paragraphs) and the whole text's ends trimmed. The words must still match
    exactly. The vault applies the same rule to what it reads from the form."""
    s = modes.plain(str(s or "").replace("\r\n", "\n"), newlines=True)
    return "\n".join(l.rstrip() for l in s.split("\n") if l.strip()).strip()


def site_of(host):
    """The site a host belongs to, by the vault's rule (broker._site): the
    last two labels, or the address itself for an IP."""
    host = (host or "").lower()
    if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
        return host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def digest(s):
    return hashlib.sha256(norm_text(s).encode()).hexdigest()


HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ------------------------------------------------------------------ storage

def migrate(c):
    c.execute("""CREATE TABLE IF NOT EXISTS plans(
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, agent_id TEXT NOT NULL,
      title TEXT NOT NULL, start_at INTEGER NOT NULL, end_at INTEGER NOT NULL,
      status TEXT NOT NULL, txn_id TEXT, created_at INTEGER, decided_at INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS plan_steps(
      plan_id TEXT NOT NULL, step TEXT NOT NULL, pos INTEGER NOT NULL,
      site TEXT NOT NULL, host TEXT NOT NULL, path TEXT, label TEXT NOT NULL,
      category TEXT NOT NULL, texts TEXT, digests TEXT, after TEXT,
      uses INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
      pre INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'waiting',
      reason TEXT, last_txn TEXT, updated_at INTEGER,
      PRIMARY KEY(plan_id, step))""")
    c.execute("CREATE INDEX IF NOT EXISTS plans_agent ON plans(agent_id, status)")


def _err(msg) -> NoReturn:
    raise ValueError(msg)


def parse(body, norm_site, now=None):
    """Validate an agent's plan. Returns (title, start, end, steps)."""
    now = now or int(time.time())
    title = re.sub(r"\s+", " ", modes.plain(body.get("title") or "")).strip()
    if not 1 <= len(title) <= 80:
        _err("title: 1 to 80 characters")
    try:
        start, end = int(body.get("start_at")), int(body.get("end_at"))
    except (TypeError, ValueError):
        _err("start_at and end_at are Unix times in seconds")
    if start < now - 60:
        _err("the window must not start in the past")
    if start > now + MAX_AHEAD:
        _err("the window must start within 30 days")
    if not 60 <= end - start <= MAX_WINDOW:
        _err("the window must last 1 minute to 24 hours")
    raw = body.get("steps")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_STEPS:
        _err(f"steps: 1 to {MAX_STEPS}")
    steps, seen = [], set()
    for i, s in enumerate(raw):
        if not isinstance(s, dict):
            _err(f"step {i + 1}: an object")
        sid = str(s.get("id") or i + 1).lower()
        if not STEP_ID.match(sid) or sid in seen:
            _err(f"step {i + 1}: id must be unique, [a-z0-9_-], up to 24 characters")
        seen.add(sid)
        url = str(s.get("url") or "").strip()
        m = re.match(r"^https://([^/?#]+)(/[^?#]*)?", url, re.I)
        if m is None:
            _err(f"step {sid}: url must be the page's https address")
        host = m.group(1).rsplit("@", 1)[-1].split(":")[0].lower()
        if not modes.HOST_RE.match(host):
            _err(f"step {sid}: not a valid address")
        path = (s.get("path") or "").strip() or None      # optional exact path, or prefix ending in *
        if path is not None and not PATH_RE.match(path):
            _err(f"step {sid}: path must start with /; it may include the query (/items?id=1), "
                 "and a trailing * matches anything after it")
        label = re.sub(r"\s+", " ", modes.plain(s.get("button") or "")).strip()
        if not 1 <= len(label) <= 80:
            _err(f"step {sid}: button: the button's words, 1 to 80 characters")
        texts = s.get("texts") or []
        if not isinstance(texts, list) or len(texts) > MAX_TEXTS or \
                not all(isinstance(t, str) and 0 < len(t) <= MAX_TEXT for t in texts):
            _err(f"step {sid}: texts: up to {MAX_TEXTS} strings of up to {MAX_TEXT} characters")
        if any(modes.has_hidden(t.replace("\n", "").replace("\r", "").replace("\t", "")) for t in texts):
            _err(f"step {sid}: a text holds hidden characters")
        cat = modes.classify(label, {})[0]
        if cat == "publish" and not texts:
            _err(f"step {sid}: '{label}' posts or sends: give the exact text in texts")
        if cat in ("delete", "unknown") and not path:
            _err(f"step {sid}: '{label}' needs the exact page path")
        after = s.get("after") or []
        if not isinstance(after, list) or not all(str(a).lower() in seen - {sid} for a in after):
            _err(f"step {sid}: after may only name earlier steps")
        try:
            uses = int(s.get("uses") or 1)
        except (TypeError, ValueError):
            uses = 0
        if not 1 <= uses <= MAX_USES:
            _err(f"step {sid}: uses 1 to {MAX_USES}")
        steps.append({"step": sid, "pos": i, "site": norm_site(site_of(host)), "host": host.removeprefix("www."),
                      "path": path, "label": label, "category": cat,
                      "texts": [norm_text(t) for t in texts],     # the card shows all of it
                      "digests": sorted(digest(t) for t in texts),
                      "after": [str(a).lower() for a in after], "uses": uses})
    return title, start, end, steps


def create(c, user_id, agent_id, title, start, end, steps, txn_id):
    pid = "p_" + secrets.token_hex(8)
    now = int(time.time())
    c.execute("INSERT INTO plans(id,user_id,agent_id,title,start_at,end_at,status,txn_id,created_at) "
              "VALUES(?,?,?,?,?,?,'pending',?,?)", (pid, user_id, agent_id, title, start, end, txn_id, now))
    for s in steps:
        c.execute("INSERT INTO plan_steps(plan_id,step,pos,site,host,path,label,category,texts,digests,after,"
                  "uses,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (pid, s["step"], s["pos"], s["site"], s["host"], s["path"], s["label"], s["category"],
                   json.dumps(s["texts"]), json.dumps(s["digests"]), json.dumps(s["after"]), s["uses"], now))
    return pid


def card(c, txn_id):
    """What the owner's plan card shows."""
    p = c.execute("SELECT * FROM plans WHERE txn_id=?", (txn_id,)).fetchone()
    if not p:
        return None
    return {"id": p["id"], "title": p["title"], "start_at": p["start_at"], "end_at": p["end_at"],
            "steps": [_step_out(r, with_text=True) for r in _steps(c, p["id"])]}


def _steps(c, pid):
    return c.execute("SELECT * FROM plan_steps WHERE plan_id=? ORDER BY pos", (pid,)).fetchall()


def _step_out(r, with_text=False):
    out = {"id": r["step"], "site": r["site"], "host": r["host"], "path": r["path"], "button": r["label"],
           "category": r["category"], "after": json.loads(r["after"] or "[]"), "uses": r["uses"],
           "used": r["used"], "pre_approved": bool(r["pre"]), "state": r["state"],
           "pre_approvable": r["category"] not in NEVER}
    if r["reason"]:
        out["reason"] = r["reason"]
    if with_text:
        out["texts"] = json.loads(r["texts"] or "[]")
    return out


def on_decision(c, t, approve, chosen=None):
    """The owner answered the plan card. `chosen`: step ids to pre-approve
    (None = all that may be). Steps not chosen ask at the time."""
    p = c.execute("SELECT * FROM plans WHERE txn_id=?", (t["id"],)).fetchone()
    if not p:
        return
    now = int(time.time())
    if not approve:
        c.execute("UPDATE plans SET status='denied', decided_at=? WHERE id=?", (now, p["id"]))
        return
    ids = {r["step"] for r in _steps(c, p["id"])}
    pick = ids if chosen is None else {str(x).lower() for x in chosen} & ids
    for r in _steps(c, p["id"]):
        pre = 1 if r["step"] in pick and r["category"] not in NEVER else 0
        c.execute("UPDATE plan_steps SET pre=?, updated_at=? WHERE plan_id=? AND step=?",
                  (pre, now, p["id"], r["step"]))
    c.execute("UPDATE plans SET status='approved', decided_at=? WHERE id=?", (now, p["id"]))


def withdraw(c, user_id, pid):
    cur = c.execute("UPDATE plans SET status='withdrawn', decided_at=? WHERE id=? AND user_id=? "
                    "AND status IN ('pending','approved')", (int(time.time()), pid, user_id))
    if cur.rowcount:
        p = c.execute("SELECT txn_id FROM plans WHERE id=?", (pid,)).fetchone()
        c.execute("UPDATE authnz_requests SET status='cancelled' WHERE id=? AND status='pending'", (p["txn_id"],))
    return bool(cur.rowcount)


def status(c, pid, agent_id=None, user_id=None, now=None):
    q, a = "SELECT * FROM plans WHERE id=?", [pid]
    if agent_id:
        q, a = q + " AND agent_id=?", a + [agent_id]
    if user_id:
        q, a = q + " AND user_id=?", a + [user_id]
    p = c.execute(q, a).fetchone()
    if not p:
        return None
    _refresh(c, p, now)
    return _plan_out(c, p, now)


def list_for(c, user_id, agent_id=None, now=None):
    now = now or int(time.time())
    q, a = "SELECT * FROM plans WHERE user_id=? AND end_at>?", [user_id, now - 7 * 86400]
    if agent_id:
        q, a = q + " AND agent_id=?", a + [agent_id]
    out = []
    for p in c.execute(q + " ORDER BY start_at DESC LIMIT 50", a).fetchall():
        _refresh(c, p, now)
        out.append(_plan_out(c, p, now))
    return out


def _plan_out(c, p, now=None):
    now = now or int(time.time())
    st = p["status"]
    if st == "pending" and now > p["end_at"]:
        st = "unanswered"
    elif st in ("approved", "pending") and now > p["end_at"]:
        st = "finished"
    return {"id": p["id"], "agent_id": p["agent_id"], "title": p["title"], "start_at": p["start_at"],
            "end_at": p["end_at"], "status": st,
            "card": "approved" if p["status"] == "approved" else
                    "not answered: every step asks at the time" if p["status"] == "pending" else p["status"],
            "steps": [_step_out(r) for r in _steps(c, p["id"])]}


# ------------------------------------------------------------------ run time

def _refresh(c, p, now=None):
    """A step whose card closed unanswered is skipped."""
    now = now or int(time.time())
    for r in _steps(c, p["id"]):
        if r["state"] != "asking" or not r["last_txn"]:
            continue
        t = c.execute("SELECT status, expires_at FROM authnz_requests WHERE id=?", (r["last_txn"],)).fetchone()
        if not t:
            continue
        if t["status"] in ("expired", "cancelled") or (t["status"] == "pending" and t["expires_at"] < now):
            _set(c, p["id"], r["step"], "skipped", "you did not answer in time")
        elif t["status"] == "denied":
            _set(c, p["id"], r["step"], "denied", "you denied it")
        elif t["status"] == "approved":
            _set(c, p["id"], r["step"], "running", None)


def _set(c, pid, step, state, reason):
    c.execute("UPDATE plan_steps SET state=?, reason=?, updated_at=? WHERE plan_id=? AND step=?",
              (state, reason, int(time.time()), pid, step))


def _path_ok(want, path):
    if not want:
        return True
    if want.endswith("*"):
        return (path or "").startswith(want[:-1])
    return (path or "") == want


def match(c, user_id, agent_id, site, details, now=None):
    """Find the plan step this approval request is. Returns None (not part
    of any plan) or a dict:
      {"plan", "step", "title", "pre": bool, "blocked": reason or None}
    Matching is exact: same agent, open window, approved or unanswered plan,
    same site and address, same button words, same path rule (path and
    query), and the same set of texts (none if the step was given none)."""
    now = now or int(time.time())
    d = details or {}
    host = (d.get("host") or "").lower().removeprefix("www.")
    label = modes.words(d.get("label") or "").lower()
    if not host or not label:
        return None
    # a form that posts to another site is never a pre-approved step: the
    # owner approved a click on this site, not a send to that one
    if modes.sends_elsewhere(site, d):
        return None
    got = d.get("text_digests")
    got = sorted(x for x in got if isinstance(x, str) and HEX64.match(x)) if isinstance(got, list) else None
    for p in c.execute("SELECT * FROM plans WHERE user_id=? AND agent_id=? AND status IN ('approved','pending') "
                       "AND start_at<=? AND end_at>? ORDER BY created_at", (user_id, agent_id, now, now)).fetchall():
        _refresh(c, p, now)
        rows = {r["step"]: r for r in _steps(c, p["id"])}
        for r in rows.values():
            if r["site"] != site or r["host"] != host or modes.words(r["label"]).lower() != label:
                continue
            if not _path_ok(r["path"], d.get("path")):
                continue
            # the texts compared exactly, both ways: a step given no text never
            # matches a click that sends some (the owner approved no words)
            if json.loads(r["digests"] or "[]") != (got or []):
                continue
            if r["used"] >= r["uses"]:
                continue
            out = {"plan": p["id"], "step": r["step"], "title": p["title"], "pos": r["pos"] + 1,
                   "plan_status": p["status"], "category": r["category"],
                   "pre": bool(r["pre"]) and p["status"] == "approved" and r["category"] not in NEVER,
                   "blocked": None}
            for a in json.loads(r["after"] or "[]"):
                dep = rows.get(a)
                if dep is None or dep["state"] == "done":
                    continue
                n = dep["pos"] + 1
                if dep["state"] in ("skipped", "denied", "failed", "unknown"):
                    out["blocked"] = (f"skipped: step {out['pos']} depends on step {n}, which "
                                      + {"skipped": "was not approved in time", "denied": "you denied",
                                         "failed": "failed", "unknown": "has an unknown result"}[dep["state"]])
                elif dep["state"] == "asking":
                    out["blocked"] = (f"not yet: step {out['pos']} depends on step {n}, which is still "
                                      "waiting for the owner")
                else:
                    out["blocked"] = (f"not yet: step {out['pos']} depends on step {n}, which has not "
                                      f"finished. Do step {n} first")
                break
            return out
    return None


def on_request(c, m, txn_id, auto):
    """Record that the request `txn_id` is plan step m. auto: approved now."""
    if m["blocked"]:
        if m["blocked"].startswith("skipped"):
            _set(c, m["plan"], m["step"], "skipped", m["blocked"].split(": ", 1)[1])
        return
    c.execute("UPDATE plan_steps SET used=used+?, state=?, last_txn=?, reason=NULL, updated_at=? "
              "WHERE plan_id=? AND step=?",
              (1 if auto else 0, "running" if auto else "asking", txn_id, int(time.time()), m["plan"], m["step"]))


def on_card_decision(c, txn_id, approve):
    """The owner answered an at-the-time card that was a plan step."""
    r = c.execute("SELECT plan_id, step FROM plan_steps WHERE last_txn=? AND state='asking'", (txn_id,)).fetchone()
    if not r:
        return
    if approve:
        c.execute("UPDATE plan_steps SET used=used+1, state='running', updated_at=? WHERE plan_id=? AND step=?",
                  (int(time.time()), r["plan_id"], r["step"]))
    else:
        _set(c, r["plan_id"], r["step"], "denied", "you denied it")


RESULTS = ("done", "failed", "unknown")


def on_result(c, agent_id, txn_id, result):
    """The vault reports what happened after an approved plan step's click.
    Returns the step's new state, or None if txn_id is not this agent's
    running plan step."""
    if result not in RESULTS:
        raise ValueError("result must be done, failed or unknown")
    r = c.execute("SELECT s.plan_id, s.step, s.used, s.uses FROM plan_steps s JOIN plans p ON p.id=s.plan_id "
                  "WHERE s.last_txn=? AND s.state='running' AND p.agent_id=?", (txn_id, agent_id)).fetchone()
    if not r:
        return None
    _set(c, r["plan_id"], r["step"], result, None if result == "done" else
         "the site did not answer" if result == "unknown" else "the click failed")
    return result
