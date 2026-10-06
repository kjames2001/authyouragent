"""Stored sign-in secrets from the owner's Bitwarden or Vaultwarden.

The vault reads the owner's own password manager (read-only) and types a
secret straight into a field of the page. The value never goes back to the
agent: the agent names an item, the vault fills it.

Only items in one folder are usable (default "Auth Your Agent"), so the owner
decides which sign-ins an agent may use by moving them into that folder.

Configuration: a JSON file mounted at /run/secrets/bitwarden.json (or the path
in VAULT_BITWARDEN_FILE):

    {"url": "https://vault.example.com",       # Bitwarden cloud: https://vault.bitwarden.com
     "email": "owner@example.com",
     "master_password": "...",                  # needed to decrypt; never sent to the server
     "client_id": "user.xxxx", "client_secret": "...",   # API key (recommended), or omit to
                                                         # sign in with the master password
     "folder": "Auth Your Agent"}               # optional

Personal items only (items owned by an organization are skipped). Decrypted
keys live in memory only; each secret is decrypted at the moment it is filled.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import time
import uuid
from urllib.parse import parse_qs, unquote, urlparse

from aiohttp import ClientSession, ClientTimeout
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

CONFIG = os.environ.get("VAULT_BITWARDEN_FILE", "/run/secrets/bitwarden.json")
SYNC_TTL = 60
DEVICE_TYPE = 23                # Linux CLI
DEVICE_ID = str(uuid.uuid4())   # one per vault start; the profile is wiped anyway


class SecretsError(Exception):
    pass


def configured():
    return os.path.isfile(CONFIG)


# ── Bitwarden crypto ──
def _b64(s):
    return base64.b64decode(s)


def _master_key(password, email, kdf):
    salt = email.strip().lower().encode()
    if kdf["kdf"] == 0:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, kdf["iterations"], 32)
    if kdf["kdf"] == 1:
        from argon2.low_level import Type, hash_secret_raw
        return hash_secret_raw(password.encode(), hashlib.sha256(salt).digest(),
                               time_cost=kdf["iterations"], memory_cost=kdf["memory"] * 1024,
                               parallelism=kdf["parallelism"], hash_len=32, type=Type.ID)
    raise SecretsError(f"unsupported key derivation ({kdf['kdf']})")


def _stretch(master_key):
    exp = lambda info: HKDFExpand(hashes.SHA256(), 32, info).derive(master_key)
    return exp(b"enc"), exp(b"mac")


def _decrypt(cs, enc_key, mac_key):
    """Decrypt a type-2 cipherstring (AES-256-CBC + HMAC-SHA256)."""
    if not cs:
        return None
    kind, _, rest = cs.partition(".")
    if kind != "2":
        raise SecretsError(f"unsupported encryption type {kind}")
    iv, ct, mac = (_b64(p) for p in rest.split("|"))
    if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac):
        raise SecretsError("a stored value failed its integrity check (wrong master password?)")
    d = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    u = padding.PKCS7(128).unpadder()
    return u.update(d.update(ct) + d.finalize()) + u.finalize()


def _encrypt(plain, enc_key, mac_key):
    """Encrypt to a type-2 cipherstring (AES-256-CBC + HMAC-SHA256)."""
    iv = os.urandom(16)
    e = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    p = padding.PKCS7(128).padder()
    ct = e.update(p.update(plain.encode()) + p.finalize()) + e.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ct, mac))


def _text(cs, key):
    v = _decrypt(cs, *key)
    return v.decode() if v is not None else None


def totp_now(spec, now=None):
    """Current code for an otpauth:// URI or a bare base32 secret (RFC 6238)."""
    spec = (spec or "").strip()
    digits, period, algo = 6, 30, "sha1"
    if spec.lower().startswith("steam://"):
        raise SecretsError("Steam Guard codes are not supported")
    if spec.lower().startswith("otpauth://"):
        q = {k.lower(): v[0] for k, v in parse_qs(urlparse(spec).query).items()}
        secret = q.get("secret", "")
        digits, period = int(q.get("digits", 6)), int(q.get("period", 30))
        algo = q.get("algorithm", "sha1").lower()
    else:
        secret = spec
    secret = unquote(secret).replace(" ", "").upper()
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((now or time.time()) // period)
    h = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


# ── matching an item to the page ──
def _origin(u):
    p = urlparse(u if "://" in u else "https://" + u)
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{p.hostname.lower()}:{port}"


def uri_allows(uri, match, page_url):
    """True if a saved address lets its secret be filled on page_url. Stricter
    than Bitwarden's default (base domain): the scheme, host and port must be
    the same, so a sister subdomain or plain http does not qualify."""
    if not uri or match == 5:                        # "never"
        return False
    if match == 3:                                   # exact
        return page_url == uri
    if match == 2:                                   # starts with
        return page_url.startswith(uri) and _origin(page_url) == _origin(uri)
    if match == 4:                                   # regular expression: not honoured
        return False
    o = _origin(uri)                                 # default / base domain / host
    return o is not None and o == _origin(page_url)


class Store:
    def __init__(self):
        self.cfg = None
        self.key = None             # user key (enc, mac), in memory only
        self.token = None
        self.token_until = 0
        self.items = {}             # name -> encrypted cipher JSON
        self.synced = 0
        self._cached_folders = []   # [{name, id}] decrypted on the last sync

    def _load(self):
        if self.cfg is None:
            try:
                with open(CONFIG) as f:
                    cfg = json.load(f)
            except OSError:
                raise SecretsError("no password manager is set up for this vault "
                                   "(start it with `authyouragent vault up --bitwarden FILE`)")
            for k in ("url", "email", "master_password"):
                if not cfg.get(k):
                    raise SecretsError(f"bitwarden config is missing '{k}'")
            cfg["url"] = cfg["url"].rstrip("/")
            cfg.setdefault("folder", "Auth Your Agent")
            self.cfg = cfg
        return self.cfg

    def _endpoints(self):
        u = self.cfg["url"]
        if urlparse(u).hostname in ("vault.bitwarden.com", "bitwarden.com"):
            return "https://identity.bitwarden.com", "https://api.bitwarden.com"
        if urlparse(u).hostname in ("vault.bitwarden.eu", "bitwarden.eu"):
            return "https://identity.bitwarden.eu", "https://api.bitwarden.eu"
        return u + "/identity", u + "/api"

    async def _login(self, s):
        cfg = self.cfg
        identity, _ = self._endpoints()
        async with s.post(identity + "/accounts/prelogin", json={"email": cfg["email"]}) as r:
            if r.status != 200:
                raise SecretsError(f"password manager prelogin failed ({r.status})")
            p = await r.json(content_type=None)
        kdf = {"kdf": p.get("kdf", p.get("Kdf", 0)),
               "iterations": p.get("kdfIterations", p.get("KdfIterations", 600000)),
               "memory": p.get("kdfMemory", p.get("KdfMemory")),
               "parallelism": p.get("kdfParallelism", p.get("KdfParallelism"))}
        mk = _master_key(cfg["master_password"], cfg["email"], kdf)
        form = {"scope": "api", "deviceType": str(DEVICE_TYPE), "deviceIdentifier": DEVICE_ID,
                "deviceName": "Auth Your Agent vault"}
        if cfg.get("client_id") and cfg.get("client_secret"):
            form.update(grant_type="client_credentials", client_id=cfg["client_id"],
                        client_secret=cfg["client_secret"])
        else:
            mph = base64.b64encode(hashlib.pbkdf2_hmac("sha256", mk, cfg["master_password"].encode(), 1, 32))
            form.update(grant_type="password", client_id="cli", username=cfg["email"],
                        password=mph.decode(), scope="api offline_access")
        async with s.post(identity + "/connect/token", data=form,
                          headers={"Device-Type": str(DEVICE_TYPE)}) as r:
            t = await r.json(content_type=None)
            if r.status != 200:
                why = t.get("ErrorModel", {}).get("Message") or t.get("error_description") or t.get("error")
                if t.get("TwoFactorProviders") or t.get("TwoFactorProviders2"):
                    why = "two-step login is on; use an API key (client_id / client_secret) instead"
                raise SecretsError(f"password manager sign-in failed: {why}")
        self.token = t["access_token"]
        self.token_until = time.time() + int(t.get("expires_in", 3600)) - 60
        protected = t.get("Key") or t.get("key")
        user_key = _decrypt(protected, *_stretch(mk)) if protected else None
        if user_key is None:
            raise SecretsError("the password manager did not return the account key")
        self.key = (user_key[:32], user_key[32:])

    async def _sync(self, force=False):
        self._load()
        if not force and self.items is not None and time.time() - self.synced < SYNC_TTL and self.key:
            return
        async with ClientSession(timeout=ClientTimeout(total=30)) as s:
            if not self.token or time.time() > self.token_until:
                await self._login(s)
            _, api = self._endpoints()
            async with s.get(api + "/sync?excludeDomains=true",
                             headers={"Authorization": "Bearer " + self.token}) as r:
                if r.status == 401:
                    self.token = None
                    raise SecretsError("password manager session expired; try again")
                if r.status != 200:
                    raise SecretsError(f"password manager sync failed ({r.status})")
                data = await r.json(content_type=None)
        lower = lambda d: {k[0].lower() + k[1:]: v for k, v in d.items()} if isinstance(d, dict) else d
        data = lower(data)
        self._cached_folders = []
        for f in data.get("folders") or []:
            f = lower(f)        # old Vaultwarden: Name/Id; new: name/id
            self._cached_folders.append(
                {"name": _text(f["name"], self.key) if f.get("name") else "", "id": f["id"]})
        folder_id = None
        for f in self._cached_folders:
            if f["name"] == self.cfg["folder"]:
                folder_id = f["id"]
        items = {}
        if folder_id:
            for c in data.get("ciphers") or []:
                c = lower(c)
                if c.get("folderId") != folder_id or c.get("organizationId") or c.get("type") != 1 \
                        or c.get("deletedDate"):
                    continue
                key = self._item_key(c)
                items[_text(c["name"], key)] = c
        self.items, self.synced = items, time.time()

    def _item_key(self, c):
        if c.get("key"):
            k = _decrypt(c["key"], *self.key)
            return k[:32], k[32:]
        return self.key

    async def list(self):
        """Usable items: name, the addresses they may be filled on, and which
        fields they have. Never a value."""
        await self._sync()
        out = []
        for name, c in sorted(self.items.items()):
            key, login = self._item_key(c), {k[0].lower() + k[1:]: v for k, v in (c.get("login") or {}).items()}
            uris = []
            for u in login.get("uris") or []:
                u = {k[0].lower() + k[1:]: v for k, v in u.items()}
                uri = _text(u.get("uri"), key)
                if uri and u.get("match") not in (4, 5):
                    uris.append(uri)
            fields = [f for f, k in (("username", "username"), ("password", "password"), ("totp", "totp"))
                      if login.get(k)]
            out.append({"name": name, "sites": uris, "fields": fields})
        return out

    async def value(self, name, field, page_url):
        """Decrypt one field of one item, only if the item may be used on page_url."""
        await self._sync()
        c = self.items.get(name)
        if c is None:
            await self._sync(force=True)
            c = self.items.get(name)
        if c is None:
            raise SecretsError(f"no item named '{name}' in the '{self.cfg['folder']}' folder")
        key = self._item_key(c)
        login = {k[0].lower() + k[1:]: v for k, v in (c.get("login") or {}).items()}
        allowed = False
        for u in login.get("uris") or []:
            u = {k[0].lower() + k[1:]: v for k, v in u.items()}
            if uri_allows(_text(u.get("uri"), key), u.get("match"), page_url):
                allowed = True
        if not allowed:
            raise SecretsError(f"'{name}' is not saved for this site ({_origin(page_url) or page_url}); "
                               "the owner can add this address to the item")
        if field == "totp":
            spec = _text(login.get("totp"), key)
            if not spec:
                raise SecretsError(f"'{name}' has no authenticator key")
            return totp_now(spec)
        v = _text(login.get(field), key)
        if not v:
            raise SecretsError(f"'{name}' has no {field}")
        return v

    def same_login(self, username, page_url):
        """The name of an item that already holds this sign-in: the same
        username (case and spaces ignored) and an address that may be used on
        page_url. None if there is none."""
        want = (username or "").strip().lower()
        for name, c in sorted(self.items.items()):
            key = self._item_key(c)
            login = {k[0].lower() + k[1:]: v for k, v in (c.get("login") or {}).items()}
            if (_text(login.get("username"), key) or "").strip().lower() != want:
                continue
            for u in login.get("uris") or []:
                u = {k[0].lower() + k[1:]: v for k, v in u.items()}
                if uri_allows(_text(u.get("uri"), key), u.get("match"), page_url):
                    return name
        return None

    async def create(self, name, username, password, page_url):
        """Create a login item in the shared folder. Returns the item name.
        Refused if the name is taken or the same sign-in is already saved."""
        await self._sync(force=True)        # another device may have saved it since the last sync
        if name in self.items:
            raise SecretsError(f"an item named '{name}' already exists in the '{self.cfg['folder']}' folder")
        dup = self.same_login(username, page_url)
        if dup:
            raise SecretsError(f"this login is already saved as '{dup}'")
        async with ClientSession(timeout=ClientTimeout(total=30)) as s:
            if not self.token or time.time() > self.token_until:
                await self._login(s)
            _, api = self._endpoints()
            folder_id = None
            for f in self._cached_folders:
                if f["name"] == self.cfg["folder"]:
                    folder_id = f["id"]
                    break
            if not folder_id:
                folder_cs = _encrypt(self.cfg["folder"], *self.key)
                async with s.post(api + "/folders", json={"name": folder_cs},
                                  headers={"Authorization": "Bearer " + self.token}) as r:
                    if r.status != 200:
                        raise SecretsError(f"could not create folder ({r.status})")
                    body = await r.json(content_type=None)
                    folder_id = body.get("Id") or body.get("id")   # old/new Vaultwarden key casing
                    if not folder_id:
                        raise SecretsError(f"could not create folder ({r.status})")
                    self._cached_folders.append({"name": self.cfg["folder"], "id": folder_id})
            key = self.key
            cipher = {
                "type": 1,
                "folderId": folder_id,
                "name": _encrypt(name, *key),
                "login": {
                    "username": _encrypt(username, *key) if username else None,
                    "password": _encrypt(password, *key) if password else None,
                    "uris": [{"uri": _encrypt(page_url, *key), "match": None}],
                },
                "notes": None,
                "favorite": False,
            }
            async with s.post(api + "/ciphers", json=cipher,
                              headers={"Authorization": "Bearer " + self.token}) as r:
                if r.status != 200:
                    body = await r.json(content_type=None)
                    why = body.get("ValidationErrors") or body.get("message") or str(r.status)
                    raise SecretsError(f"could not save the login: {why}")
            await self._sync(force=True)
        return name


STORE = Store()
