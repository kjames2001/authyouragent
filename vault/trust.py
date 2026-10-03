"""Trusted sites: the owner's own exceptions to the vault's rules.

The owner lists sites in a file the agent cannot write through the vault
(mounted read-only, edited with `authyouragent vault trust`):

    {"sites": {"example.com": {"approvals": false},
               "10.8.6.3:8123": {"private": true, "approvals": false}}}

- "approvals": false  clicks and form submits on that site do not ask the
  owner each time. Saved passwords stay hidden from the agent as always.
- "private": true      the browser may open that exact host (or host:port) on
  the owner's own network. Only private ranges (10/8, 172.16/12, 192.168/16,
  100.64/10 such as Tailscale, IPv6 ULA): loopback, link-local (cloud
  metadata) and the vault itself stay blocked whatever the file says.

An entry takes effect only after the owner confirms it on their phone, once
per session (until end_session). A changed or removed entry needs a new
confirmation.
"""
import ipaddress
import json
import os
import re

PATH = os.environ.get("VAULT_TRUST_FILE", "/run/secrets/trusted.json")
_HOST = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$")

_mtime = None
_sites = {}
_confirmed = {}          # key -> the entry it was confirmed for
_declined = {}           # key -> the entry the owner refused this session


def _load():
    global _mtime, _sites
    try:
        m = os.stat(PATH).st_mtime_ns
    except OSError:
        _mtime, _sites = None, {}
        _confirmed.clear()
        _declined.clear()
        return
    if m == _mtime:
        return
    _mtime = m
    try:
        raw = json.load(open(PATH)).get("sites", {})
    except Exception:
        raw = {}
    sites = {}
    for k, v in (raw.items() if isinstance(raw, dict) else []):
        k = str(k).strip().lower()
        if not _HOST.match(k) or not isinstance(v, dict) or k.split(":")[0] in ("localhost", ""):
            continue
        sites[k] = {"approvals": v.get("approvals", True) is not False, "private": v.get("private") is True}
    _sites = sites
    for d in (_confirmed, _declined):
        for k in list(d):
            if d[k] != sites.get(k):
                del d[k]


def entries():
    _load()
    return dict(_sites)


def _match(host, port, site, want):
    """The entry key covering host[:port] (exact host:port, then host, then
    the registrable site for approval-only entries), or None."""
    _load()
    host = (host or "").lower()
    keys = [f"{host}:{port}"] if port else []
    keys.append(host)
    if want == "approvals" and site:
        keys.append(site)
    for k in keys:
        e = _sites.get(k)
        if e and ((want == "approvals" and not e["approvals"]) or (want == "private" and e["private"])):
            return k
    return None


def approvals_key(host, port, site):
    return _match(host, port, site, "approvals")


def private_key(host, port):
    return _match(host, port, None, "private")


def confirmed(key):
    _load()
    return key in _confirmed and _confirmed[key] == _sites.get(key)


def confirm(key):
    _load()
    if key in _sites:
        _confirmed[key] = dict(_sites[key])


def decline(key):
    _load()
    if key in _sites:
        _declined[key] = dict(_sites[key])


def declined(key):
    _load()
    return key in _declined and _declined[key] == _sites.get(key)


def reset():
    _confirmed.clear()
    _declined.clear()


def private_ip_ok(ip):
    """A trusted private address: the owner's LAN or tailnet, never loopback,
    link-local, unspecified, multicast or reserved."""
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast or a.is_reserved:
        return False
    if isinstance(a, ipaddress.IPv4Address):
        return any(a in ipaddress.ip_network(n) for n in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
    return a in ipaddress.ip_network("fc00::/7")


def private_allowed(host, port):
    k = private_key(host, port)
    return bool(k) and confirmed(k)
