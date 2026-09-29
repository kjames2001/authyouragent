import type { AgentClient } from "./index.js";

export type TakeoverResult = "done" | "cancelled" | "expired" | "agent_left" | "incomplete";

export interface TakeoverOptions {
  /** Returns true when the job is really finished. Enables automatic handback. */
  check?: ((page: any) => Promise<boolean>) | null;
  /** How many times to ask again if `check` still fails after a handback. Default 1. */
  retries?: number;
  /** Size the page is shown at while the person is in control. null keeps the agent's own. */
  phoneSize?: [number, number] | null;
  quality?: number;
  onLive?: (() => void) | null;
  /** Skip TLS checks (local test servers only). */
  insecure?: boolean;
  retryReason?: string;
}

/** Text-only check: true when no password or one-time-code field is showing. */
export declare function loginFinished(page: any): Promise<boolean>;

/** Ask the owner to take over a Playwright `page`. Needs the `ws` package. */
export declare function takeover(agent: AgentClient, page: any, reason: string,
                                 options?: TakeoverOptions): Promise<TakeoverResult>;
