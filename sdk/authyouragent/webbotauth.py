"""Web Bot Auth: sign HTTP requests so websites can recognise an agent.

Implements the signer side of draft-ietf-webbotauth-httpsig-protocol on top of
HTTP Message Signatures (RFC 9421), with Ed25519 keys:

- every request carries ``Signature-Agent`` (the HTTPS address where the
  agent's public keys are published), ``Signature-Input`` and ``Signature``;
- the key directory is a JWK Set served at
  ``/.well-known/http-message-signatures-directory`` of that address, signed
  once per key (Appendix B) so it cannot be copied to another address.

The Web Bot Auth key is separate from the agent key (the draft: key reuse
considered harmful). ``Signature-Agent`` is sent as a single quoted string,
the form Cloudflare verifies today; the draft lets verifiers accept it.
"""
import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TAG = "web-bot-auth"
DIRECTORY_TAG = "http-message-signatures-directory"
WELL_KNOWN = "/.well-known/http-message-signatures-directory"
MEDIA_TYPE = "application/http-message-signatures-directory+json"
REQUEST_LIFETIME = 300          # seconds a request signature stays valid
DIRECTORY_LIFETIME = 3600      # seconds the directory's possession proof stays valid: a copy of the
                               # key list passed on elsewhere stops counting an hour after a revoke


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── keys ──
def new_key():
    return Ed25519PrivateKey.generate()


def key_to_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def key_from_pem(pem):
    key = serialization.load_pem_private_key(pem.encode() if isinstance(pem, str) else pem, None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Web Bot Auth key must be Ed25519")
    return key


def public_jwk(key):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


def thumbprint(jwk):
    """RFC 7638 / RFC 8037 JWK thumbprint: the Web Bot Auth ``keyid``."""
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
                       separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canon.encode()).digest())


def jwk_public_key(jwk):
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(_unb64u(jwk["x"]))


# ── RFC 9421 pieces ──
def _params(components, created, expires, keyid, tag, nonce=None):
    out = f"({' '.join(components)});created={created};keyid=\"{keyid}\";alg=\"ed25519\";expires={expires}"
    if nonce:
        out += f";nonce=\"{nonce}\""
    return out + f";tag=\"{tag}\""


def _base(lines, params):
    return "\n".join(lines + [f"\"@signature-params\": {params}"]).encode()


def authority(url):
    """RFC 9421 @authority: lower-case host, port only when not the default."""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = u.port
    if port and not ((u.scheme == "https" and port == 443) or (u.scheme == "http" and port == 80)):
        host += f":{port}"
    return host


def content_digest(body):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


# ── the key directory ──
def directory_body(jwk):
    """The exact bytes served at the well-known address (one key)."""
    entry = {"kty": jwk["kty"], "crv": jwk["crv"], "kid": thumbprint(jwk), "x": jwk["x"], "use": "sig"}
    return json.dumps({"keys": [entry]}, separators=(",", ":")).encode()


def sign_directory(key, body, host, now=None, lifetime=DIRECTORY_LIFETIME):
    """Possession proof for the directory response (draft Appendix B), bound to
    ``host`` (the directory's authority) and to the body through Content-Digest."""
    now = int(now or time.time())
    digest = content_digest(body)
    params = _params(['"@authority";req', '"content-digest"'], now, now + lifetime,
                     thumbprint(public_jwk(key)), DIRECTORY_TAG)
    sig = key.sign(_base([f"\"@authority\";req: {host}", f"\"content-digest\": {digest}"], params))
    return {"Content-Digest": digest, "Signature-Input": f"binding={params}",
            "Signature": f"binding=:{base64.b64encode(sig).decode()}:"}


# ── signing a request ──
def sign_request(key, method, url, signature_agent, now=None, lifetime=REQUEST_LIFETIME):
    """Headers to add to one request. ``signature_agent`` is the HTTPS origin
    that publishes the directory. Covers the authority, method and path, so a
    copied signature cannot be replayed against another page or method."""
    now = int(now or time.time())
    u = urlsplit(url)
    agent_value = f"\"{signature_agent}\""
    params = _params(['"@authority"', '"@method"', '"@path"', '"signature-agent"'],
                     now, now + lifetime, thumbprint(public_jwk(key)), TAG,
                     nonce=base64.b64encode(secrets.token_bytes(64)).decode())
    base = _base([f"\"@authority\": {authority(url)}", f"\"@method\": {method.upper()}",
                  f"\"@path\": {u.path or '/'}", f"\"signature-agent\": {agent_value}"], params)
    return {"Signature-Agent": agent_value, "Signature-Input": f"sig1={params}",
            "Signature": f"sig1=:{base64.b64encode(key.sign(base)).decode()}:"}


# ══════════════════════════════════════════════════════════════════════════
# Verifying a request (draft-ietf-webbotauth-httpsig-protocol-00)
# ══════════════════════════════════════════════════════════════════════════
#
#     from authyouragent import webbotauth
#     result = webbotauth.verify(request)          # Starlette/FastAPI, Flask, Django, httpx
#     if result.verified:
#         print(result.agent)                     # the URL the keys were fetched from
#
# Works for any agent's key list, not only Auth Your Agent's. verify() blocks on
# the network the first time it sees a key list: in async code call it with
# ``await asyncio.to_thread(webbotauth.verify, request)``.

import http.client
import ipaddress
import socket
import ssl
import threading
import zlib
from urllib.parse import parse_qsl, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import _sfv as sfv

VERIFIED, INVALID, UNVERIFIED, UNSIGNED = "verified", "invalid", "unverified", "unsigned"

# Thumbprints of the example keys in RFC 9421 Appendix B.1 (the draft's vectors
# and Cloudflare's demo directory use them). Draft 6.8: reject them in production.
TEST_KEYS = frozenset({
    "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",   # test-key-ed25519
    "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA",   # test-key-rsa-pss
    "BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo",   # test-key-rsa
    "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI",   # test-key-ecc-p256
})

_UA = "authyouragent-webbotauth (+https://authyouragent.com/docs/developers/web-bot-auth)"


class Result:
    """Outcome of :func:`verify` (draft Appendix C.1).

    ``outcome`` is ``verified`` (signature and key check out), ``invalid`` (the
    signature, its covered parts, the key or its times are wrong),
    ``unverified`` (not enough to decide, e.g. the key list could not be
    fetched or does not hold the key) or ``unsigned`` (no Web Bot Auth
    signature). ``agent`` is set only when verified: the URL the keys were
    fetched from, which is what the draft says to attach policy to."""

    __slots__ = ("outcome", "reason", "agent", "signature_agent", "keyid", "label",
                 "domain_proof", "stale", "created", "expires", "others")

    def __init__(self, outcome, reason="", agent=None, signature_agent=None, keyid=None,
                 label=None, domain_proof=None, stale=False, created=None, expires=None):
        self.outcome, self.reason, self.agent = outcome, reason, agent
        self.signature_agent, self.keyid, self.label = signature_agent, keyid, label
        self.domain_proof, self.stale = domain_proof, stale
        self.created, self.expires = created, expires
        self.others = []

    @property
    def verified(self):
        return self.outcome == VERIFIED

    def to_dict(self):
        d = {k: getattr(self, k) for k in self.__slots__ if k != "others"}
        d["others"] = [o.to_dict() for o in self.others]
        return d

    def __repr__(self):
        who = self.agent or self.signature_agent or "-"
        return f"<Result {self.outcome} {who} {self.reason!r}>"


class _Invalid(Exception):
    pass


class _Unverified(Exception):
    pass


# ── the request being checked ──
def _header_lists(headers):
    out = {}
    if headers is None:
        return out
    items = headers.items() if hasattr(headers, "items") else headers
    for k, v in items:
        if isinstance(k, bytes):
            k = k.decode("latin-1")
        vals = v if isinstance(v, (list, tuple)) else [v]
        for one in vals:
            if isinstance(one, bytes):
                one = one.decode("latin-1")
            out.setdefault(k.lower(), []).append(str(one))
    return out


_PATH_SAFE = "/:@!$&'()*+,;=-._~%"


def _from_request(request):
    """(method, url as the client sent it, headers) from a framework request.
    @path and @query must be the encoded bytes the client sent, not the
    decoded path frameworks hand to routes."""
    method = request.method
    if hasattr(request, "build_absolute_uri"):                       # Django
        origin = request.build_absolute_uri("/")[:-1]
    else:
        u = urlsplit(str(request.url))
        origin = f"{u.scheme}://{u.netloc}"
    scope = getattr(request, "scope", None)
    environ = getattr(request, "environ", None)
    if not isinstance(environ, dict):
        environ = getattr(request, "META", None)
    if isinstance(scope, dict) and isinstance(scope.get("raw_path"), (bytes, bytearray)):   # ASGI
        path = scope["raw_path"].decode("latin-1")
        query = (scope.get("query_string") or b"").decode("latin-1")
    elif isinstance(environ, dict):                                                         # WSGI
        raw = environ.get("RAW_URI") or environ.get("REQUEST_URI")   # gunicorn, werkzeug / uWSGI
        if raw:
            if "://" in raw.split("?", 1)[0]:
                raw = urlunsplit(("", "") + tuple(urlsplit(raw)[2:4]) + ("",))
            path, _, query = raw.partition("?")
            if "?" not in raw:
                query = environ.get("QUERY_STRING", "")
        else:
            # the server gave only the decoded path: re-encode it. PEP 3333
            # servers UTF-8-decode it, so utf-8 brings back the client's bytes.
            # An encoded slash (%2F) cannot be recovered.
            from urllib.parse import quote
            dec = (environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")).encode("utf-8")
            path, query = quote(dec, safe=_PATH_SAFE), environ.get("QUERY_STRING", "")
    else:
        u = urlsplit(str(request.url))
        path, query = u.path, u.query
    return method, origin + (path or "/") + ("?" + query if query else ""), getattr(request, "headers", None)


def _form_encode(s):
    """WHATWG application/x-www-form-urlencoded byte serialiser with %20 for
    space, as RFC 9421 2.2.8 shows."""
    return "".join(chr(b) if (chr(b).isascii() and chr(b).isalnum()) or chr(b) in "*-._" else "%%%02X" % b
                   for b in s.encode("utf-8"))


class _Msg:
    def __init__(self, method, url, headers):
        self.method, self.url = str(method), str(url)
        self.u = urlsplit(self.url)
        self.h = _header_lists(headers)

    def field(self, name):
        vals = self.h.get(name)
        if vals is None:
            return None
        return ", ".join(v.strip(" \t") for v in vals)

    def component(self, name, params):
        if name.startswith("@"):
            allowed = {"name"} if name == "@query-param" else set()
            if set(params) - allowed:
                raise _Unverified(f"component parameter {sorted(set(params) - allowed)} on {name} not supported")
            u = self.u
            if name == "@method":
                return self.method
            if name == "@target-uri":
                return self.url
            if name == "@authority":
                return authority(self.url)
            if name == "@scheme":
                return u.scheme.lower()
            if name == "@path":
                return u.path or "/"
            if name == "@query":
                return "?" + u.query
            if name == "@request-target":
                return (u.path or "/") + ("?" + u.query if u.query else "")
            if name == "@query-param":
                want = params.get("name")
                if not isinstance(want, str) or isinstance(want, sfv.Token):
                    raise _Invalid("@query-param needs a name")
                hits = [v for k, v in parse_qsl(u.query, keep_blank_values=True) if _form_encode(k) == want]
                if len(hits) != 1:
                    raise _Invalid(f"query parameter {want!r} {'missing' if not hits else 'repeated'}")
                return _form_encode(hits[0])
            raise _Unverified(f"component {name} not supported")
        if set(params) - {"key"}:
            raise _Unverified(f"component parameter {sorted(set(params) - {'key'})} on {name} not supported")
        raw = self.field(name)
        if raw is None:
            raise _Invalid(f"covered header {name} is missing")
        if "key" in params:
            try:
                d = sfv.parse_dictionary(raw)
            except sfv.SFError as e:
                raise _Invalid(f"header {name} is not a dictionary: {e}")
            if params["key"] not in d:
                raise _Invalid(f"header {name} has no member {params['key']!r}")
            return sfv.ser_member(d[params["key"]])
        return raw

    def base(self, covered, member):
        lines = []
        for name, params in covered:
            if not isinstance(name, str) or isinstance(name, sfv.Token) or name != name.lower():
                raise _Invalid("component names must be lower-case strings")
            val = self.component(name, params)
            if "\n" in val or "\r" in val:
                raise _Invalid(f"component {name} contains a line break")
            lines.append(f"{sfv.ser_item(name, params)}: {val}")
        lines.append(f'"@signature-params": {sfv.ser_member(member)}')
        return "\n".join(lines).encode()


# ── keys ──
def _int_b64(s):
    return int.from_bytes(_unb64u(s), "big")


def _load_jwk(jwk):
    """(thumbprint, public key, kind) for a well-formed public JWK, else None."""
    if not isinstance(jwk, dict) or any(k in jwk for k in ("d", "p", "q", "k")):
        return None
    try:
        kty = jwk.get("kty")
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            raw = _unb64u(jwk["x"])
            if len(raw) != 32:
                return None
            return thumbprint(jwk), Ed25519PublicKey.from_public_bytes(raw), "ed25519"
        if kty == "EC" and jwk.get("crv") in ("P-256", "P-384"):
            curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1()
            pub = ec.EllipticCurvePublicNumbers(_int_b64(jwk["x"]), _int_b64(jwk["y"]), curve).public_key()
            canon = json.dumps({"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
                               separators=(",", ":"), sort_keys=True)
            return b64u(hashlib.sha256(canon.encode()).digest()), pub, jwk["crv"]
        if kty == "RSA":
            pub = rsa.RSAPublicNumbers(_int_b64(jwk["e"]), _int_b64(jwk["n"])).public_key()
            if pub.key_size < 2048:
                return None
            canon = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"), sort_keys=True)
            return b64u(hashlib.sha256(canon.encode()).digest()), pub, "RSA:" + str(jwk.get("alg") or "")
    except Exception:
        return None
    return None


_ALG_FOR = {"ed25519": {"ed25519"}, "P-256": {"ecdsa-p256-sha256"}, "P-384": {"ecdsa-p384-sha384"}}


def _check_sig(pub, kind, alg, sig, base):
    if alg is not None and (not isinstance(alg, str) or isinstance(alg, sfv.Token)):
        raise _Invalid("alg must be a string")
    if alg == "hmac-sha256":
        raise _Invalid("shared-secret signatures are not allowed (draft 6.4)")
    if kind.startswith("RSA:"):
        jwk_alg = kind[4:]
        alg = alg or {"PS512": "rsa-pss-sha512", "RS256": "rsa-v1_5-sha256"}.get(jwk_alg)
        if alg not in ("rsa-pss-sha512", "rsa-v1_5-sha256"):
            raise _Invalid("RSA signature without a usable alg")
    else:
        ok = _ALG_FOR[kind]
        alg = alg or next(iter(ok))
        if alg not in ok:
            raise _Invalid(f"alg {alg} does not match the {kind} key")
    try:
        if alg == "ed25519":
            pub.verify(sig, base)
        elif alg == "rsa-pss-sha512":
            pub.verify(sig, base, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
        elif alg == "rsa-v1_5-sha256":
            pub.verify(sig, base, padding.PKCS1v15(), hashes.SHA256())
        else:
            n = 32 if alg == "ecdsa-p256-sha256" else 48
            if len(sig) != 2 * n:
                raise InvalidSignature()
            der = encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
            pub.verify(der, base, ec.ECDSA(hashes.SHA256() if n == 32 else hashes.SHA384()))
    except InvalidSignature:
        raise _Invalid("signature does not verify")
    return alg


# ── fetching key lists safely (draft 6.7) ──
def _public_ip(ip):
    a = ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not (a.is_multicast or a.is_unspecified or a.is_reserved)


def https_get(url, *, timeout=5.0, max_bytes=65536, allow_private=False, accept=MEDIA_TYPE):
    """GET one https URL with the draft's SSRF limits: a wall-clock timeout, a
    size cap after decoding, no redirects (a 3xx is returned as is), and only
    public addresses (the connection goes to the address that was checked, so
    DNS rebinding cannot swap it). Returns (status, {header: value}, body)."""
    u = urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise _Unverified("key list must be fetched over https")
    deadline = time.monotonic() + timeout
    port = u.port or 443
    try:
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise _Unverified(f"cannot resolve {u.hostname}: {e}")
    addrs = [i[4][0] for i in infos]
    usable = addrs if allow_private else [a for a in addrs if _public_ip(a)]
    if not usable:
        raise _Unverified(f"{u.hostname} resolves only to non-public addresses")
    last = None
    for ip in usable[:3]:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        try:
            raw = socket.create_connection((ip, port), timeout=left)
        except OSError as e:
            last = e
            continue
        # a hard deadline: a server that trickles bytes defeats per-read socket timeouts.
        # wrap_socket detaches `raw`, so the watchdog must close whichever socket is live.
        live = [raw]

        def _cut():
            try:
                live[0].shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        watchdog = threading.Timer(max(0.0, deadline - time.monotonic()), _cut)
        watchdog.daemon = True
        watchdog.start()
        try:
            raw.settimeout(max(0.1, deadline - time.monotonic()))
            conn = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
            live[0] = conn
        except (OSError, ssl.SSLError) as e:
            watchdog.cancel()
            raw.close()
            if time.monotonic() >= deadline:
                raise _Unverified("key list fetch timed out")
            raise _Unverified(f"TLS to {u.hostname} failed: {e}")
        try:
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            conn.settimeout(max(0.1, deadline - time.monotonic()))
            conn.sendall((f"GET {path} HTTP/1.1\r\nHost: {authority(url)}\r\nAccept: {accept}\r\n"
                          f"Accept-Encoding: identity\r\nUser-Agent: {_UA}\r\nConnection: close\r\n\r\n").encode())
            resp = http.client.HTTPResponse(conn, method="GET")
            resp.begin()
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            enc = hdrs.get("content-encoding", "identity").strip().lower()
            dec = zlib.decompressobj(16 + zlib.MAX_WBITS) if enc in ("gzip", "x-gzip") else \
                zlib.decompressobj() if enc == "deflate" else None
            if enc not in ("identity", "", "gzip", "x-gzip", "deflate"):
                raise _Unverified(f"key list sent with unsupported content-encoding {enc}")
            body = b""
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise _Unverified("key list fetch timed out")
                conn.settimeout(left)
                chunk = resp.read(8192)
                if not chunk:
                    break
                body += dec.decompress(chunk, max_bytes + 1 - len(body)) if dec else chunk
                if len(body) > max_bytes:
                    raise _Unverified(f"key list larger than {max_bytes} bytes")
            if dec:
                body += dec.flush()
                if len(body) > max_bytes:
                    raise _Unverified(f"key list larger than {max_bytes} bytes")
            return resp.status, hdrs, body
        except (OSError, http.client.HTTPException, ValueError) as e:
            if time.monotonic() >= deadline:
                raise _Unverified("key list fetch timed out")
            raise _Unverified(f"fetching the key list failed: {e.__class__.__name__}")
        finally:
            watchdog.cancel()
            conn.close()
    raise _Unverified(f"cannot connect to {u.hostname}: {last}")


# ── key lists ──
def _origin(u):
    host = (u.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{u.port}" if u.port and u.port != 443 else "")


_UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _norm_path(p):
    """RFC 3986 6.2.2: upper-case percent escapes, decode unreserved, drop dot segments."""
    out, i = [], 0
    while i < len(p):
        if p[i] == "%" and i + 2 < len(p) + 0 and len(p[i + 1:i + 3]) == 2:
            ch = chr(int(p[i + 1:i + 3], 16)) if all(c in "0123456789abcdefABCDEF" for c in p[i + 1:i + 3]) else None
            out.append(ch if ch in _UNRESERVED else p[i:i + 3].upper())
            i += 3
        else:
            out.append(p[i])
            i += 1
    segs = []
    for s in "".join(out).split("/"):
        if s == "..":
            if len(segs) > 1:
                segs.pop()
        elif s != ".":
            segs.append(s)
    return "/".join(segs) or "/"


def _identifier(value, typ):
    """(identifier, fetch URL) for one Signature-Agent member (draft 5.5)."""
    u = urlsplit(value)
    if u.scheme.lower() != "https" or not u.hostname or u.username is not None or u.password is not None:
        raise _Unverified("Signature-Agent must be an https URL")
    try:
        u.port
    except ValueError:
        raise _Unverified("Signature-Agent has a bad port")
    if typ == "directory":
        if u.path not in ("", "/") or u.query or u.fragment or "?" in value or "#" in value:
            raise _Unverified("a directory Signature-Agent must be an origin (scheme and host only)")
        url = _origin(u) + WELL_KNOWN
        return url, url
    if typ == "jwks_uri":
        return _origin(u) + _norm_path(u.path or "/"), value
    raise _Unverified(f"Signature-Agent type {typ!r} not supported")


def _ttl(hdrs, default, cap):
    cc = {}
    for part in hdrs.get("cache-control", "").split(","):
        k, _, v = part.strip().partition("=")
        if k:
            cc[k.lower()] = v.strip('"')
    if "no-store" in cc or "no-cache" in cc:
        return 0
    ttl = None
    if cc.get("max-age", "").isdigit():
        ttl = int(cc["max-age"])
    elif "expires" in hdrs:
        from email.utils import parsedate_to_datetime
        try:
            exp = parsedate_to_datetime(hdrs["expires"]).timestamp()
            date = parsedate_to_datetime(hdrs["date"]).timestamp() if "date" in hdrs else time.time()
            ttl = max(0, int(exp - date))
        except (TypeError, ValueError, IndexError):
            ttl = 0
    if ttl is None:
        ttl = default
    age = hdrs.get("age", "")
    if age.isdigit():
        ttl -= int(age)
    return max(0, min(ttl, cap))


def _seconds(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v / 1000 if v > 1e11 else v      # Cloudflare's demo directory writes nbf in milliseconds


def _digest_ok(field, body):
    try:
        d = sfv.parse_dictionary(field)
    except sfv.SFError:
        return False
    algs = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
    seen = False
    for name, (val, _p) in d.items():
        if name in algs:
            if not isinstance(val, bytes) or algs[name](body).digest() != val:
                return False
            seen = True
    return seen


class _KeyList:
    __slots__ = ("keys", "test_keys", "proof", "fetched", "fresh_until")


def _parse_list(status, hdrs, body, typ, host, now, max_keys):
    if status != 200:
        raise _Unverified(f"key list answered HTTP {status}")
    ctype = hdrs.get("content-type", "").split(";")[0].strip().lower()
    if typ == "directory" and ctype != MEDIA_TYPE:
        raise _Unverified(f"key list served as {ctype or 'no content-type'}, not {MEDIA_TYPE}")
    try:
        doc = json.loads(body)
    except ValueError:
        raise _Unverified("key list is not JSON")
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        raise _Unverified("key list has no keys array")
    if len(keys) > max_keys:
        raise _Unverified(f"key list holds more than {max_keys} keys")
    kl = _KeyList()
    kl.keys, kl.test_keys, kl.proof = {}, set(), {}
    for jwk in keys:
        got = _load_jwk(jwk)
        if not got:
            continue
        thumb, pub, kind = got
        if typ == "directory" and "kid" in jwk and jwk["kid"] != thumb:
            continue                                  # draft 5.5: kid must be the thumbprint
        nbf, exp = _seconds(jwk.get("nbf")), _seconds(jwk.get("exp"))
        if (nbf is not None and nbf > now + 60) or (exp is not None and exp <= now):
            continue
        if thumb in TEST_KEYS:
            kl.test_keys.add(thumb)
        kl.keys[thumb] = (pub, kind)
    if typ == "directory":
        kl.proof = _directory_proof(hdrs, body, host, kl.keys, now)
    return kl


def _directory_proof(hdrs, body, host, keys, now):
    """Appendix B: which keys signed this response for this host. {thumb: True}."""
    out = {}
    if "signature-input" not in hdrs or "signature" not in hdrs or "content-digest" not in hdrs:
        return out
    if not _digest_ok(hdrs["content-digest"], body):
        return out
    try:
        inputs = sfv.parse_dictionary(hdrs["signature-input"])
        sigs = sfv.parse_dictionary(hdrs["signature"])
    except sfv.SFError:
        return out
    for label, member in inputs.items():
        covered, params = member
        if not isinstance(covered, list) or params.get("tag") != DIRECTORY_TAG:
            continue
        thumb = params.get("keyid")
        names = [(n, dict(p)) for n, p in covered]
        if thumb not in keys or ("@authority", {"req": True}) not in names or ("content-digest", {}) not in names:
            continue
        created, expires = params.get("created"), params.get("expires")
        if not isinstance(created, int) or not isinstance(expires, int) or created > now + 60 or expires <= now:
            continue
        sig = sigs.get(label, (None, {}))[0]
        if not isinstance(sig, bytes):
            continue
        lines = []
        for n, p in names:
            if n == "@authority":
                lines.append(f'"@authority";req: {host}')
            elif n == "content-digest":
                lines.append(f'"content-digest": {hdrs["content-digest"].strip()}')
            else:
                lines = None
                break
        if lines is None:
            continue
        base = "\n".join(lines + [f'"@signature-params": {sfv.ser_member(member)}']).encode()
        pub, kind = keys[thumb]
        try:
            _check_sig(pub, kind, params.get("alg"), sig, base)
            out[thumb] = True
        except _Invalid:
            pass
    return out


class Verifier:
    """Checks Web Bot Auth signatures from any agent and keeps fetched key lists.

    One Verifier per process is enough; it is thread-safe. Defaults follow
    the draft: signatures may live at most ``max_lifetime`` seconds (24 h),
    key lists are cached as their Cache-Control says (at most ``max_ttl``),
    a key list that cannot be fetched keeps its last good copy for
    ``max_stale`` seconds (draft 6.10), failures are cached ``negative_ttl``
    seconds, and the RFC 9421 example keys are refused.

    A key list is reused for at least ``min_ttl`` seconds even when it says
    ``no-store``, so a busy agent does not cause one fetch per request; this
    also bounds how late a removed key stops verifying. Set it to 0 to follow
    Cache-Control exactly. At most ``max_entries`` agents are remembered.

    ``fetch(url) -> (status, headers, body)`` replaces the network fetch, for
    tests or a framework's own HTTP client; it must apply the same limits."""

    def __init__(self, *, max_lifetime=86400, clock_skew=60, timeout=5.0, max_bytes=65536, max_keys=32,
                 allow_private=False, allow_test_keys=False, fetch=None, default_ttl=300, max_ttl=86400,
                 min_ttl=60, max_stale=86400, negative_ttl=60, refetch_after=60, max_entries=5000):
        self.max_lifetime, self.clock_skew = max_lifetime, clock_skew
        self.timeout, self.max_bytes, self.max_keys = timeout, max_bytes, max_keys
        self.allow_private, self.allow_test_keys = allow_private, allow_test_keys
        self.default_ttl, self.max_ttl, self.max_stale = default_ttl, max_ttl, max_stale
        self.min_ttl, self.max_entries = min_ttl, max_entries
        self.negative_ttl, self.refetch_after = min(negative_ttl, 300), refetch_after
        self._fetch = fetch or (lambda url: https_get(url, timeout=self.timeout, max_bytes=self.max_bytes,
                                                      allow_private=self.allow_private))
        self._cache, self._neg, self._locks = {}, {}, {}
        self._guard = threading.Lock()

    # key lists
    def _lock_for(self, ident):
        with self._guard:
            if ident not in self._locks and len(self._locks) >= self.max_entries:
                self._trim()
            return self._locks.setdefault(ident, threading.Lock())

    def _trim(self):
        """Forget the least recently fetched agents (caller holds _guard)."""
        now = time.time()
        for k in [k for k, v in self._neg.items() if v[0] <= now]:
            del self._neg[k]
        idle = [k for k, lk in self._locks.items() if not lk.locked()]
        idle.sort(key=lambda k: self._cache[k].fetched if k in self._cache else 0)
        for k in idle[:max(1, len(idle) // 4)]:
            self._locks.pop(k, None)
            self._cache.pop(k, None)
            self._neg.pop(k, None)

    def _resolve(self, ident, url, typ, now, force=False):
        """(key list, stale) for one identifier; coalesces concurrent fetches."""
        with self._lock_for(ident):
            held = self._cache.get(ident)
            if held and not force and now < held.fresh_until:
                return held, False
            neg = self._neg.get(ident)
            if neg and now < neg[0]:
                if held and now - held.fetched < self.max_stale:
                    return held, True
                raise _Unverified(neg[1])
            try:
                try:
                    status, hdrs, body = self._fetch(url)
                except _Unverified:
                    raise
                except Exception as e:
                    raise _Unverified(f"fetching the key list failed: {e.__class__.__name__}")
                hdrs = {str(k).lower(): str(v) for k, v in dict(hdrs).items()}
                kl = _parse_list(status, hdrs, bytes(body), typ, authority(url), now, self.max_keys)
            except _Unverified as e:
                self._neg[ident] = (now + self.negative_ttl, str(e))
                if held and now - held.fetched < self.max_stale:
                    return held, True
                raise
            kl.fetched = now
            kl.fresh_until = now + max(self.min_ttl, _ttl(hdrs, self.default_ttl, self.max_ttl))
            self._cache[ident] = kl                    # newer resolution wins (draft 4.4)
            self._neg.pop(ident, None)
            return kl, False

    def resolve(self, signature_agent, type="directory", now=None):
        """Fetch (or reuse) one agent's key list. Returns a dict with the
        identifier, the key thumbprints, which keys carry a valid domain proof
        (Appendix B), and whether the copy is stale."""
        now = int(now or time.time())
        ident, url = _identifier(signature_agent, type)
        kl, stale = self._resolve(ident, url, type, now)
        return {"agent": ident, "keys": sorted(kl.keys), "test_keys": sorted(kl.test_keys),
                "domain_proof": sorted(kl.proof), "stale": stale}

    # requests
    def verify(self, request=None, *, method=None, url=None, headers=None, now=None):
        """Check every Web Bot Auth signature on one request. Pass a framework
        request object, or ``method``, ``url`` (as received, including the
        query) and ``headers``. Returns a :class:`Result`; the first verified
        signature wins, otherwise the most telling failure."""
        if request is not None:
            method, url, headers = _from_request(request)
        now = int(now or time.time())
        msg = _Msg(method, url, headers)
        si, sg = msg.field("signature-input"), msg.field("signature")
        if not si and not sg:
            return Result(UNSIGNED, "no signature")
        try:
            inputs = sfv.parse_dictionary(si or "")
            sigs = sfv.parse_dictionary(sg or "")
        except sfv.SFError as e:
            return Result(INVALID, f"cannot parse Signature-Input or Signature: {e}")
        results = []
        for label, member in inputs.items():
            covered, params = member
            if not isinstance(covered, list) or params.get("tag") != TAG:
                continue                                       # draft 5.4: not a Web Bot Auth signature
            results.append(self._one(msg, label, member, sigs.get(label), now))
        if not results:
            return Result(UNSIGNED, "no web-bot-auth signature")
        rank = {VERIFIED: 0, INVALID: 1, UNVERIFIED: 2}
        results.sort(key=lambda r: rank[r.outcome])
        best = results[0]
        best.others = results[1:]
        return best

    def _one(self, msg, label, member, sig_member, now):
        covered, params = member
        keyid = params.get("keyid")
        r = Result(UNVERIFIED, label=label, keyid=keyid if isinstance(keyid, str) else None,
                   created=params.get("created"), expires=params.get("expires"))
        try:
            sig = sig_member[0] if sig_member else None
            if not isinstance(sig, bytes):
                raise _Invalid("no matching Signature value")
            created, expires = params.get("created"), params.get("expires")
            if not isinstance(created, int) or isinstance(created, bool) or \
                    not isinstance(expires, int) or isinstance(expires, bool):
                raise _Invalid("created and expires are required")
            if created > now + self.clock_skew:
                raise _Invalid("signature created in the future")
            if expires <= now - self.clock_skew:
                raise _Invalid("signature expired")
            if self.max_lifetime is not None and expires - created > self.max_lifetime:
                raise _Invalid(f"signature valid for {expires - created} s, more than {self.max_lifetime} s")
            if not isinstance(keyid, str) or isinstance(keyid, sfv.Token):
                raise _Invalid("keyid is required")
            names = [(n, dict(p)) for n, p in covered]
            if not any(n in ("@authority", "@target-uri") for n, _ in names):
                raise _Invalid("signature covers neither @authority nor @target-uri")
            base = msg.base(names, member)
            # the Signature-Agent member this signature covers (draft 5.2.1, 5.2.2)
            agent_parts = [p for n, p in names if n == "signature-agent"]
            if len(agent_parts) != 1:
                raise _Unverified("signature must cover exactly one Signature-Agent member"
                                  if agent_parts else "signature does not cover Signature-Agent")
            raw = msg.field("signature-agent") or ""
            if "key" in agent_parts[0]:
                value, mparams = sfv.parse_dictionary(raw)[agent_parts[0]["key"]]
            else:
                value, mparams = sfv.parse_item(raw)        # legacy sf-string form
            if not isinstance(value, str) or isinstance(value, sfv.Token):
                raise _Unverified("Signature-Agent member is not a string")
            r.signature_agent = value
            typ = mparams.get("type", "directory")
            ident, url = _identifier(value, str(typ))
            kl, stale = self._resolve(ident, url, str(typ), now)
            if keyid not in kl.keys and not stale and now - kl.fetched >= self.refetch_after:
                kl, stale = self._resolve(ident, url, str(typ), now, force=True)   # a key may have been added
            if keyid not in kl.keys:
                raise _Unverified("the key list does not hold this keyid")
            if keyid in kl.test_keys and not self.allow_test_keys:
                raise _Invalid("signed with a published test key (draft 6.8)")
            pub, kind = kl.keys[keyid]
            _check_sig(pub, kind, params.get("alg"), sig, base)
            r.outcome, r.agent, r.stale = VERIFIED, ident, stale
            r.domain_proof = keyid in kl.proof if str(typ) == "directory" else None
            r.reason = "signature verified" + (" with a stale key list" if stale else "")
        except _Invalid as e:
            r.outcome, r.reason = INVALID, str(e)
        except _Unverified as e:
            r.outcome, r.reason = UNVERIFIED, str(e)
        except (sfv.SFError, KeyError) as e:
            r.outcome, r.reason = UNVERIFIED, f"cannot read Signature-Agent: {e}"
        return r


_default = None
_default_lock = threading.Lock()


def verify(request=None, **kw):
    """:meth:`Verifier.verify` on a shared default :class:`Verifier`."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Verifier()
    return _default.verify(request, **kw)
