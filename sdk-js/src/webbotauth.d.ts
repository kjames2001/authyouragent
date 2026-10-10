// Type definitions for authyouragent/webbotauth.

export declare const TAG: "web-bot-auth";
export declare const DIRECTORY_TAG: "http-message-signatures-directory";
export declare const WELL_KNOWN: "/.well-known/http-message-signatures-directory";
export declare const MEDIA_TYPE: "application/http-message-signatures-directory+json";
export declare const REQUEST_LIFETIME: number;
export declare const DIRECTORY_LIFETIME: number;
export declare const VERIFIED: "verified";
export declare const INVALID: "invalid";
export declare const UNVERIFIED: "unverified";
export declare const UNSIGNED: "unsigned";
export declare const TEST_KEYS: Set<string>;

export type Outcome = "verified" | "invalid" | "unverified" | "unsigned";

export interface Result {
  outcome: Outcome;
  /** true when outcome is "verified" */
  readonly verified: boolean;
  /** Plain-language reason. */
  reason: string;
  /** Only when verified: the URL the keys were fetched from (attach policy to this). */
  agent: string | null;
  /** The Signature-Agent value the signature named. */
  signatureAgent: string | null;
  keyid: string | null;
  label: string | null;
  /** Directory lists: whether the key also signed the list for its host (draft Appendix B). */
  domainProof: boolean | null;
  /** Verified from a cached copy because the key list could not be fetched. */
  stale: boolean;
  created: number | null;
  expires: number | null;
  /** Results for the request's other Web Bot Auth signatures. */
  others: Result[];
}

export type HeadersLike = Headers | Record<string, string | string[] | undefined> | Array<[string, string]> | string[];

export interface RequestLike {
  method?: string;
  /** Absolute URL, or the raw request target (Node/Express). */
  url?: string;
  originalUrl?: string;
  headers?: HeadersLike;
  socket?: { encrypted?: boolean };
}

export interface VerifyOptions {
  method?: string;
  /** The URL as the client sent it, including the query. */
  url?: string;
  headers?: HeadersLike;
  /** Seconds since the epoch (tests). */
  now?: number;
  /** Public origin for requests that carry only a path, e.g. "https://shop.example". */
  publicBaseUrl?: string;
}

export type FetchFn = (url: string) => Promise<[number, Record<string, string>, Uint8Array]>;

export interface VerifierOptions {
  maxLifetime?: number | null;
  clockSkew?: number;
  timeout?: number;
  maxBytes?: number;
  maxKeys?: number;
  allowPrivate?: boolean;
  allowTestKeys?: boolean;
  fetch?: FetchFn | null;
  defaultTtl?: number;
  maxTtl?: number;
  minTtl?: number;
  maxStale?: number;
  negativeTtl?: number;
  refetchAfter?: number;
  maxEntries?: number;
  publicBaseUrl?: string;
}

export declare class Unverified extends Error {}

export declare class Verifier {
  constructor(options?: VerifierOptions);
  verify(request?: Request | RequestLike | null, options?: VerifyOptions): Promise<Result>;
  resolve(signatureAgent: string, type?: "directory" | "jwks_uri", now?: number): Promise<{
    agent: string; keys: string[]; testKeys: string[]; domainProof: string[]; stale: boolean;
  }>;
}

/** Verifier.verify on a shared default Verifier. */
export declare function verify(request?: Request | RequestLike | null, options?: VerifyOptions): Promise<Result>;

export declare function thumbprint(jwk: Record<string, string>): Promise<string>;
export declare function authority(url: string): string;
export declare function identifier(value: string, type?: string): [string, string];
export declare function isPublicAddress(ip: string): boolean;
export declare function ttl(headers: Record<string, string>, def: number, cap: number): number;
export declare function httpsGet(url: string, options?: { timeout?: number; maxBytes?: number; allowPrivate?: boolean; accept?: string; ca?: string }): Promise<[number, Record<string, string>, Uint8Array]>;

// signing (the agent side)
export declare function newKey(): Promise<CryptoKeyPair>;
export declare function publicJwk(key: CryptoKeyPair | CryptoKey): Promise<{ kty: "OKP"; crv: "Ed25519"; x: string }>;
export declare function signRequest(key: CryptoKeyPair, method: string, url: string, signatureAgent: string,
  options?: { now?: number; lifetime?: number }): Promise<Record<"Signature-Agent" | "Signature-Input" | "Signature", string>>;
export declare function directoryBody(jwk: { kty: string; crv: string; x: string }): Promise<Uint8Array>;
export declare function signDirectory(key: CryptoKeyPair, body: Uint8Array, host: string,
  options?: { now?: number; lifetime?: number }): Promise<Record<"Content-Digest" | "Signature-Input" | "Signature", string>>;
