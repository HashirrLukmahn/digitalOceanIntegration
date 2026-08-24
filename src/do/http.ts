import { apiBaseUrl, requireDigitalOceanToken } from "../lib/env";
import { sanitizeError, scrubString } from "../lib/redact";

/**
 * The DigitalOcean HTTP transport.
 *
 * Read-only by construction: there is no method parameter, so adding a write means
 * adding a code path. For a tool that holds credentials to someone else's cloud, that
 * speed bump is worth more than the flexibility it costs.
 *
 * Everything above this layer talks to the `DoHttp` interface, which is what lets
 * fixture mode exercise the real collectors against recorded payloads.
 */

export interface DoHttp {
  /** GET an absolute-from-root path (e.g. "/v2/droplets") or a full URL. */
  get<T>(pathOrUrl: string, query?: QueryParams): Promise<T>;
}

export type QueryParams = Record<string, string | number | boolean | undefined>;

export class DoApiError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    message: string,
  ) {
    super(message);
    this.name = "DoApiError";
  }

  /** 401/403 mean the token is wrong or under-scoped -- retrying will not help. */
  get isAuthError(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

export class DoAuthError extends DoApiError {
  constructor(path: string, status: number) {
    super(
      status,
      path,
      status === 401
        ? "DigitalOcean rejected the token (401). Check that DIGITALOCEAN_TOKEN is set to a valid token."
        : "DigitalOcean denied the request (403). The token is valid but lacks the required read scope.",
    );
    this.name = "DoAuthError";
  }
}

export interface LiveHttpOptions {
  baseUrl?: string;
  /** Total attempts per request, including the first. */
  maxAttempts?: number;
  timeoutMs?: number;
  /** Injected in tests so retry logic does not actually sleep. */
  sleep?: (ms: number) => Promise<void>;
  fetchImpl?: typeof fetch;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Live transport.
 *
 * The token is read per request from the environment and lives only in the local
 * `headers` object for the duration of the call. It is never stored on the instance,
 * so nothing that inspects or serialises this object can reach it.
 */
export class LiveDoHttp implements DoHttp {
  readonly #baseUrl: string;
  readonly #maxAttempts: number;
  readonly #timeoutMs: number;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #fetch: typeof fetch;

  constructor(options: LiveHttpOptions = {}) {
    this.#baseUrl = options.baseUrl ?? apiBaseUrl();
    this.#maxAttempts = options.maxAttempts ?? 4;
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#sleep = options.sleep ?? defaultSleep;
    this.#fetch = options.fetchImpl ?? fetch;
  }

  async get<T>(pathOrUrl: string, query?: QueryParams): Promise<T> {
    const url = new URL(pathOrUrl, this.#baseUrl);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    // Path only, for error messages -- a full URL could carry a token in a query string
    // if DigitalOcean ever added one, and error messages travel further than we expect.
    const safePath = url.pathname;

    let lastError: unknown;
    for (let attempt = 1; attempt <= this.#maxAttempts; attempt += 1) {
      try {
        const response = await this.#fetch(url, {
          method: "GET",
          headers: {
            authorization: `Bearer ${requireDigitalOceanToken()}`,
            accept: "application/json",
            "user-agent": "do-cloud-security/1.0",
          },
          signal: AbortSignal.timeout(this.#timeoutMs),
        });

        if (response.status === 401 || response.status === 403) {
          throw new DoAuthError(safePath, response.status);
        }

        // 429 and 5xx are transient. Respect Retry-After when DigitalOcean sends it,
        // otherwise back off exponentially.
        if (response.status === 429 || response.status >= 500) {
          if (attempt < this.#maxAttempts) {
            const retryAfter = Number(response.headers.get("retry-after"));
            const delay =
              Number.isFinite(retryAfter) && retryAfter > 0
                ? retryAfter * 1000
                : Math.min(2 ** attempt * 250, 8_000);
            await this.#sleep(delay);
            continue;
          }
          throw new DoApiError(
            response.status,
            safePath,
            `DigitalOcean ${safePath} failed after ${this.#maxAttempts} attempts (${response.status}).`,
          );
        }

        if (!response.ok) {
          const body = await response.text().catch(() => "");
          throw new DoApiError(
            response.status,
            safePath,
            `DigitalOcean ${safePath} failed (${response.status}): ${scrubString(body).slice(0, 300)}`,
          );
        }

        return (await response.json()) as T;
      } catch (error) {
        // An auth error will not improve on retry; a bad path will not either.
        if (error instanceof DoApiError && (error.isAuthError || error.status < 500)) throw error;
        lastError = error;
        if (attempt >= this.#maxAttempts) break;
        await this.#sleep(Math.min(2 ** attempt * 250, 8_000));
      }
    }

    throw new DoApiError(0, safePath, `DigitalOcean ${safePath} unreachable: ${sanitizeError(lastError)}`);
  }
}
