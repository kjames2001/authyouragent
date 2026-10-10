// Base64 helpers (standard and URL-safe alphabets).
export function b64Encode(bytes) {
  // standard base64, no padding needed by callers that add ":" delimiters
  let s = "";
  const b = bytes;
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
    s += A2[(n >> 18) & 63] + A2[((n >> 12) & 63)];
    s += i + 1 < b.length ? A2[((n >> 6) & 63)] : "=";
    s += i + 2 < b.length ? A2[n & 63] : "=";
  }
  return s;
}
export function b64uEncode(bytes) {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64uDecode(s) {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return b64StdDecode(std);
}
export function b64StdDecode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let buf = 0, bits = 0, out = [];
  for (const ch of s) {
    if (ch === "=") break;
    const idx = A.indexOf(ch);
    if (idx < 0) throw new Error("bad base64");
    buf = (buf << 6) | idx;
    bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}
const A2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
