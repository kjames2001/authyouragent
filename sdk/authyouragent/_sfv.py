"""The subset of RFC 8941 Structured Field Values that HTTP Message Signatures
(RFC 9421) and Web Bot Auth need: dictionaries, inner lists, items and
parameters, parsed and serialised. Serialisation is canonical, so a signature
base rebuilt from parsed values matches what a conforming signer signed."""
import base64
import re

__all__ = ["Token", "SFError", "parse_dictionary", "parse_item", "ser_item", "ser_inner_list",
           "ser_params", "ser_member"]


class SFError(ValueError):
    pass


class Token(str):
    """An sf-token (unquoted), kept apart from sf-string."""


_KEY = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_TOKEN = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_INT = re.compile(r"-?[0-9]{1,15}(\.[0-9]{1,3})?")


class _P:
    def __init__(self, s):
        if any(ord(c) > 126 or (ord(c) < 32 and c != "\t") for c in s):
            raise SFError("non-ASCII or control character in field")
        self.s, self.i = s, 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def ows(self):
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def sp(self):
        while self.peek() == " ":
            self.i += 1

    def key(self):
        m = _KEY.match(self.s, self.i)
        if not m:
            raise SFError(f"bad key at {self.i}")
        self.i = m.end()
        return m.group()

    def bare(self):
        c = self.peek()
        if c == '"':
            self.i += 1
            out = []
            while True:
                if self.i >= len(self.s):
                    raise SFError("unterminated string")
                c = self.s[self.i]
                self.i += 1
                if c == "\\":
                    if self.i >= len(self.s) or self.s[self.i] not in '"\\':
                        raise SFError("bad escape")
                    out.append(self.s[self.i])
                    self.i += 1
                elif c == '"':
                    return "".join(out)
                else:
                    out.append(c)
        if c == ":":
            end = self.s.find(":", self.i + 1)
            if end < 0:
                raise SFError("unterminated byte sequence")
            raw = self.s[self.i + 1:end]
            if not re.fullmatch(r"[A-Za-z0-9+/=]*", raw):
                raise SFError("bad byte sequence")
            self.i = end + 1
            try:
                return base64.b64decode(raw + "=" * (-len(raw) % 4))
            except Exception as e:
                raise SFError("bad base64") from e
        if c == "?":
            v = self.s[self.i + 1:self.i + 2]
            if v not in ("0", "1"):
                raise SFError("bad boolean")
            self.i += 2
            return v == "1"
        if c == "-" or c.isdigit():
            m = _INT.match(self.s, self.i)
            if not m:
                raise SFError("bad number")
            self.i = m.end()
            return float(m.group()) if m.group(1) else int(m.group())
        m = _TOKEN.match(self.s, self.i)
        if not m:
            raise SFError(f"bad item at {self.i}")
        self.i = m.end()
        return Token(m.group())

    def params(self):
        out = {}
        while self.peek() == ";":
            self.i += 1
            self.sp()
            k = self.key()
            v = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare()
            out[k] = v
        return out

    def item(self):
        return self.bare(), self.params()

    def inner_list(self):
        self.i += 1  # "("
        items = []
        while True:
            self.sp()
            if self.peek() == ")":
                self.i += 1
                return items, self.params()
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise SFError("bad inner list")

    def member(self):
        return self.inner_list() if self.peek() == "(" else self.item()


def parse_dictionary(s):
    """Dictionary -> {key: (value, params)}; value is a list of (item, params)
    for an inner list. Later duplicates override earlier ones (RFC 8941 4.2.2)."""
    p = _P(s)
    p.sp()
    out = {}
    if not p.peek():
        return out
    while True:
        k = p.key()
        if p.peek() == "=":
            p.i += 1
            out[k] = p.member()
        else:
            out[k] = (True, p.params())
        p.ows()
        if not p.peek():
            return out
        if p.peek() != ",":
            raise SFError(f"expected ',' at {p.i}")
        p.i += 1
        p.ows()
        if not p.peek():
            raise SFError("trailing comma")


def parse_item(s):
    p = _P(s)
    p.sp()
    v = p.item()
    p.sp()
    if p.peek():
        raise SFError("trailing characters")
    return v


def _ser_bare(v):
    if v is True:
        return "?1"
    if v is False:
        return "?0"
    if isinstance(v, Token):
        return str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".") if v != int(v) else f"{int(v)}.0"
    if isinstance(v, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(v)).decode() + ":"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFError(f"cannot serialise {type(v).__name__}")


def ser_params(params):
    return "".join(f";{k}" if v is True else f";{k}={_ser_bare(v)}" for k, v in params.items())


def ser_item(value, params=None):
    return _ser_bare(value) + ser_params(params or {})


def ser_inner_list(items, params=None):
    return "(" + " ".join(ser_item(v, p) for v, p in items) + ")" + ser_params(params or {})


def ser_member(member):
    value, params = member
    return ser_inner_list(value, params) if isinstance(value, list) else ser_item(value, params)
