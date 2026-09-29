// Type definitions for the Auth Your Agent JavaScript SDK.

export declare const DEFAULT_CLOUD: string;
export declare const VERSION: string;

export declare class AgentError extends Error {
  status?: number;
  /** "revoked" | "no_grant" | "denied" | "expired" | "timeout" | undefined */
  code?: string;
}

export declare class AuthError extends Error {
  /** Machine-readable reason, e.g. "access token expired", "DPoP: url mismatch". */
  error: string;
}

export interface AgentKey {
  privateKeyPem: string;
  publicKeyPem: string;
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
}

/** Generate an agent key pair locally. Register `jwk` in the app; keep `privateKeyPem` secret. */
export declare function keygen(): Promise<AgentKey>;

export interface AgentClientOptions {
  agentId: string;
  privateKeyPem: string;
  baseUrl?: string;
  pollInterval?: number;
  approvalTimeout?: number;
  fetch?: typeof fetch;
}

export interface EnsureGrantOptions {
  /** Wait for the person to answer (default true). */
  wait?: boolean;
  /** Information about the person the site should receive, e.g. ["user:name"]. */
  userInfo?: Array<"user:name" | "user:email" | "user:phone">;
}

export declare class AgentClient {
  constructor(options: AgentClientOptions);
  readonly agentId: string;
  /** Ask for access to a site. Resolves true once approved, null with wait:false. */
  ensureGrant(site: string, scopes: string[], options?: EnsureGrantOptions): Promise<true | null>;
  /** Call a site with the pass and a fresh DPoP proof. */
  fetch(url: string, init?: RequestInit & { stepupAction?: string; site?: string }): Promise<Response>;
  /** A DPoP proof for one request (for custom HTTP clients). */
  dpopProof(method: string, url: string, accessToken?: string): Promise<string>;
}

export interface SiteVerifierOptions {
  baseUrl?: string;
  expectedAudience?: string;
  publicBaseUrl?: string;
  mode?: "cloud" | "local";
  revTtl?: number;
  maxStale?: number;
  fetch?: typeof fetch;
}

export interface VerifiedAgent {
  agentId: string;
  /** Filled in cloud mode only. */
  agentName?: string;
  userId: string;
  site: string;
  scopes: string[];
  userInfo: Record<string, string>;
  stepup: boolean;
}

/** Anything with a method, a url and headers: a Fetch API Request or a Node/Express request. */
export interface RequestLike {
  method?: string;
  url?: string;
  headers: Headers | Record<string, string | string[] | undefined>;
}

export declare class SiteVerifier {
  constructor(options?: SiteVerifierOptions);
  expectedUrl(req: RequestLike, url?: string): string;
  /** Throws AuthError if the request is not from an approved agent. */
  verify(req: RequestLike, options?: { url?: string; action?: string }): Promise<VerifiedAgent>;
}
