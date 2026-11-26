// Type declarations for sandboxd-client (cycle 6, FR-CL1.2).

export declare const VERSION: string;

export type Language = "python" | "javascript";

/** File content: text is sent as is, bytes are sent base64-encoded. */
export type FileContent = string | Uint8Array | ArrayBuffer;
/** Input files, read-only under /in: `{ "data.csv": "a,b\n" }` or `[["raw.bin", bytes]]`. */
export type Files = Record<string, FileContent> | Array<[string, FileContent]>;

/** Optional limits; they can only tighten the policy. Examples: "2s", "5G", "128MiB". */
export interface Limits {
  wall_clock?: string;
  fuel?: string;
  memory?: string;
  stdout?: string;
  stderr?: string;
}

export interface RunOptions {
  language?: Language;
  policy?: string;
  files?: Files;
  args?: string[];
  stdin?: string;
  limits?: Limits;
}

export interface SessionRunOptions {
  files?: Files;
  args?: string[];
  /** Only `wall_clock` and `fuel`, tighter than the session's, for this call. */
  limits?: Pick<Limits, "wall_clock" | "fuel">;
}

export interface SessionOptions {
  language?: Language;
  policy?: string;
  files?: Files;
  limits?: Limits;
}

export interface Artifact {
  name: string;
  size: number;
  sha256: string;
  content: Uint8Array;
  text(): string;
}

export interface ErrorInfo {
  code: string;
  message: string;
}

export interface Timings {
  queuedMs: number;
  setupMs: number;
  runMs: number;
  collectMs: number;
  totalMs: number;
}

export type Outcome = "ok" | "exit" | "limit" | "trap" | "error";

export interface RunResult {
  runId: string;
  language: string;
  policy: string;
  outcome: Outcome | string;
  /** `outcome === "ok"`. */
  ok: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  stdoutBytes: Uint8Array;
  stderrBytes: Uint8Array;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  artifacts: Artifact[];
  /** The artifact with this name; throws if there is none. */
  artifact(name: string): Artifact;
  limitsHit: string[];
  error: ErrorInfo | null;
  fuelUsed: number;
  peakMemory: number;
  timings: Timings;
  sessionId: string | null;
  sessionEnded: string | null;
  /** The response as sent by the server. */
  raw: Record<string, unknown>;
}

export type StreamEvent =
  | { type: "stdout" | "stderr"; text: string; data: Uint8Array }
  | { type: "limit"; limit: string }
  | { type: "result"; result: RunResult };

export interface Policy {
  name: string;
  description: string;
  overridesBuiltin: boolean;
  wallClock: string;
  memory: string;
  mounts: string[];
}

export interface SessionInfo {
  sessionId: string;
  language: string;
  policy: string;
  interpreter: string;
  state: "active" | "busy" | "ended" | string;
  endedReason: string | null;
  calls: number;
  maxCalls: number;
  createdAt: string;
  expiresAt: string;
  idleTimeoutS: number;
}

/** The server refused a request, or could not be reached (`code === "UNREACHABLE"`). */
export declare class SandboxdError extends Error {
  readonly code: string;
  /** HTTP status, or null when no response arrived. */
  readonly status: number | null;
  /** The server's message. */
  readonly detail: string;
  constructor(code: string, message: string, status?: number | null);
}

export declare class Session {
  readonly client: Sandboxd;
  readonly id: string;
  lastInfo: SessionInfo | null;
  run(code: string, opts?: SessionRunOptions): Promise<RunResult>;
  stream(code: string, opts?: SessionRunOptions): AsyncGenerator<StreamEvent, void, undefined>;
  info(): Promise<SessionInfo>;
  close(): Promise<SessionInfo>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface ClientOptions {
  /** Default: $SANDBOXD_URL, then http://127.0.0.1:8080. */
  url?: string;
  /** Default: $SANDBOXD_TOKEN. */
  token?: string;
  /** Per request (until the response headers for streams). Default 300000. */
  timeoutMs?: number;
  /** Retries for 429 answers, honouring Retry-After. Default 3. */
  retries?: number;
  fetch?: typeof fetch;
  userAgent?: string;
}

export declare class Sandboxd {
  readonly url: string;
  timeoutMs: number;
  retries: number;
  constructor(opts?: ClientOptions);
  run(code: string, opts?: RunOptions): Promise<RunResult>;
  stream(code: string, opts?: RunOptions): AsyncGenerator<StreamEvent, void, undefined>;
  createSession(opts?: SessionOptions): Promise<Session>;
  session(id: string): Session;
  policies(): Promise<Policy[]>;
  health(): Promise<{ status: string }>;
}
