// The subset of RFC 8941 Structured Field Values that HTTP Message Signatures
// (RFC 9421) and Web Bot Auth need: dictionaries, inner lists, items and
// parameters, parsed and serialised. Serialisation is canonical, so a signature
// base rebuilt from parsed values matches what a conforming signer signed.
//
// Parsed bare values are tagged so a quoted string, an unquoted token, a byte
// sequence, a boolean and a number stay distinct (the Python port keeps this
// split with `class Token(str)`). Tag object: { t, v, isInt? }.
//   t: 'str' | 'tok' | 'bytes' | 'bool' | 'num'
import { b64Encode } from "./_b64.js";

export class SFError extends Error {}

const KEY = /[a-z*][a-z0-9_\-.*]*/y;
const TOKEN = /[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:\/]*/y;
const INT = /-?[0-9]{1,15}(\.[0-9]{1,3})?/y;

class P {
  constructor(s) {
    for (const c of s) {
      const o = c.codePointAt(0);
      if (o > 126 || (o < 32 && c !== "\t")) throw new SFError("non-ASCII or control character in field");
    }
    this.s = s;
    this.i = 0;
  }
  peek() { return this.i < this.s.length ? this.s[this.i] : ""; }
  ows() { while (this.peek() === " " || this.peek() === "\t") this.i++; }
  sp() { while (this.peek() === " ") this.i++; }
  key() {
    KEY.lastIndex = this.i;
    const m = KEY.exec(this.s);
    if (!m) throw new SFError(`bad key at ${this.i}`);
    this.i = m.index + m[0].length;
    return m[0];
  }
  bare() {
    let c = this.peek();
    if (c === '"') {
      this.i++;
      const out = [];
      for (;;) {
        if (this.i >= this.s.length) throw new SFError("unterminated string");
        c = this.s[this.i]; this.i++;
        if (c === "\\") {
          if (this.i >= this.s.length || (this.s[this.i] !== '"' && this.s[this.i] !== "\\"))
            throw new SFError("bad escape");
          out.push(this.s[this.i]); this.i++;
        } else if (c === '"') {
          return { t: "str", v: out.join("") };
        } else out.push(c);
      }
    }
    if (c === ":") {
      const end = this.s.indexOf(":", this.i + 1);
      if (end < 0) throw new SFError("unterminated byte sequence");
      const raw = this.s.slice(this.i + 1, end);
      if (!/^[A-Za-z0-9+/=]*$/.test(raw)) throw new SFError("bad byte sequence");
      this.i = end + 1;
      return { t: "bytes", v: b64DecodePadded(raw) };
    }
    if (c === "?") {
      const v = this.s[this.i + 1];
      if (v !== "0" && v !== "1") throw new SFError("bad boolean");
      this.i += 2;
      return { t: "bool", v: v === "1" };
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      INT.lastIndex = this.i;
      const m = INT.exec(this.s);
      if (!m) throw new SFError("bad number");
      this.i = m.index + m[0].length;
      const isInt = m[1] === undefined;
      return { t: "num", v: Number(m[0]), isInt };
    }
    TOKEN.lastIndex = this.i;
    const m = TOKEN.exec(this.s);
    if (!m) throw new SFError(`bad item at ${this.i}`);
    this.i = m.index + m[0].length;
    return { t: "tok", v: m[0] };
  }
  params() {
    const out = {};
    while (this.peek() === ";") {
      this.i++;
      this.sp();
      const k = this.key();
      let v = { t: "bool", v: true };
      if (this.peek() === "=") { this.i++; v = this.bare(); }
      out[k] = v;
    }
    return out;
  }
  item() {
    const value = this.bare();
    const params = this.params();
    return [value, params];
  }
  innerList() {
    this.i++; // consume "("
    const items = [];
    for (;;) {
      this.sp();
      if (this.peek() === ")") { this.i++; return [items, this.params()]; }
      items.push(this.item());
      if (this.peek() !== " " && this.peek() !== ")") throw new SFError("bad inner list");
    }
  }
  member() {
    return this.peek() === "(" ? this.innerList() : this.item();
  }
}

// standard base64 decode (RFC 8941 byte-seq uses the standard alphabet)
function b64DecodePadded(raw) {
  const pad = raw;
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let buf = 0, bits = 0, out = [];
  for (const ch of pad) {
    if (ch === "=") break;
    const idx = A.indexOf(ch);
    if (idx < 0) throw new SFError("bad base64");
    buf = (buf << 6) | idx; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

// Dictionary -> {key: [value, params]}; for an inner list, value is a list of
// [item, params]. Later duplicates override earlier ones (RFC 8941 4.2.2).
export function parseDictionary(s) {
  const p = new P(s);
  p.sp();
  const out = {};
  if (!p.peek()) return out;
  for (;;) {
    const k = p.key();
    if (p.peek() === "=") { p.i++; out[k] = p.member(); }
    else out[k] = [{ t: "bool", v: true }, p.params()];
    p.ows();
    if (!p.peek()) return out;
    if (p.peek() !== ",") throw new SFError(`expected ',' at ${p.i}`);
    p.i++;
    p.ows();
    if (!p.peek()) throw new SFError("trailing comma");
  }
}

export function parseItem(s) {
  const p = new P(s);
  p.sp();
  const v = p.item();
  p.sp();
  if (p.peek()) throw new SFError("trailing characters");
  return v;
}

export function serBare(v) {
  if (typeof v === "string") return '"' + v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  if (v.t === "bool") return v.v ? "?1" : "?0";
  if (v.t === "tok") return v.v;
  if (v.t === "num") return v.isInt ? String(v.v) : numStr(v.v);
  if (v.t === "bytes") return ":" + b64Encode(v.v) + ":";
  if (v.t === "str") return '"' + v.v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  throw new SFError(`cannot serialise ${v.t}`);
}
function numStr(v) {
  let s = v.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
  return s;
}
export function serParams(params) {
  return Object.entries(params).map(([k, v]) => (v.t === "bool" && v.v ? `;${k}` : `;${k}=${serBare(v)}`)).join("");
}
export function serItem(value, params) {
  return serBare(value) + serParams(params || {});
}
export function serInnerList(items, params) {
  return "(" + items.map(([v, p]) => serItem(v, p)).join(" ") + ")" + serParams(params || {});
}
export function serMember(member) {
  const [value, params] = member;
  return Array.isArray(value) ? serInnerList(value, params) : serItem(value, params);
}
