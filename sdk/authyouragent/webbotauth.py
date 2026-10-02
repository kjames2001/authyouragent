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
DIRECTORY_LIFETIME = 7 * 86400  # seconds the directory's possession proof stays valid


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
