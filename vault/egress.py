"""Egress filter: the browser's only way out.

Chromium sends every request through this local proxy (loopback included, see
--proxy-bypass-list=<-loopback>). The proxy resolves each host itself, refuses
any address that is not on the public internet (loopback, private ranges,
link-local such as cloud metadata, CGNAT, multicast, ...), and connects to the
exact address it checked, so a DNS answer cannot change between the check and
the connection. This keeps the agent (and any page) away from the browser's
debug port, the vault's own API, and the owner's local network.

VAULT_ALLOW_HOSTS (comma separated host or host:port) lets named test hosts
through; it is for local testing only.
"""
import asyncio
import ipaddress
import os
import socket

PORT = 3128
ALLOW = {h.strip().lower() for h in os.environ.get("VAULT_ALLOW_HOSTS", "").split(",") if h.strip()}
IDLE_S = 300


def _public(ip):
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


async def _resolve(host, port):
    if (host.lower() in ALLOW) or (f"{host.lower()}:{port}" in ALLOW):
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return infos[0][4][0]
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = [i[4][0] for i in infos]
    if not ips or not all(_public(ip) for ip in ips):
        return None
    return ips[0]


async def _pipe(r, w):
    try:
        while True:
            data = await asyncio.wait_for(r.read(65536), IDLE_S)
            if not data:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


def _split_hostport(s, default):
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = s.rpartition(":") if s.count(":") == 1 else (s, "", "")
    return host, int(port) if port.isdigit() else default


async def _refuse(w, why):
    # X-Vault-Blocked lets the broker tell this refusal from a site's own 403.
    w.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Vault-Blocked: 1\r\n"
            b"Connection: close\r\n\r\n"
            + f"Blocked by the Auth Your Agent vault: {why}\n".encode())
    try:
        await w.drain()
    finally:
        w.close()


async def _handle(cr, cw):
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 30)
    except Exception:
        cw.close()
        return
    line, _, rest = head.partition(b"\r\n")
    try:
        method, target, version = line.decode("latin-1").split(" ", 2)
    except ValueError:
        cw.close()
        return
    path = ""
    if method == "CONNECT":
        host, port = _split_hostport(target, 443)
    else:
        if not target.lower().startswith("http://"):
            return await _refuse(cw, "unsupported request")
        hp, _, path = target[7:].partition("/")
        host, port = _split_hostport(hp, 80)
    try:
        ip = await _resolve(host, port)
    except Exception:
        return await _refuse(cw, f"cannot resolve {host}")
    if ip is None:
        return await _refuse(cw, f"{host} is not a public internet address")
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection(ip, port), 20)
    except Exception:
        return await _refuse(cw, f"cannot connect to {host}")
    if method == "CONNECT":
        cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await cw.drain()
    else:
        # plain http: forward the request with an origin-form target
        uw.write(f"{method} /{path} {version}\r\n".encode("latin-1") + rest)
        await uw.drain()
    await asyncio.gather(_pipe(cr, uw), _pipe(ur, cw))


async def start():
    return await asyncio.start_server(_handle, "127.0.0.1", PORT)
