// BearerSession is the one token-plus-renewal state machine every bearer-authenticated service
// uses: the mail client's own session (client.ts) and a deployment's second service (the
// product's account service). A minter re-mints the token on demand — from the in-memory key,
// never from stored credentials — and renewals are single-flighted, so a burst of concurrent
// 401s (the mailbox poll plus another call) triggers exactly one.
export class BearerSession {
  private token: string | null = null;
  private minter: (() => Promise<string | null>) | null = null;
  private inflight: Promise<string | null> | null = null;

  get(): string | null {
    return this.token;
  }

  set(token: string | null): void {
    this.token = token;
  }

  // setMinter installs (or removes) the renewal hook. dropToken also forgets the current token:
  // a handler change means the identity behind it changed (login, logout, account switch).
  setMinter(fn: (() => Promise<string | null>) | null, opts: { dropToken?: boolean } = {}): void {
    this.minter = fn;
    if (opts.dropToken) this.token = null;
  }

  canRenew(): boolean {
    return this.minter !== null;
  }

  // renew mints a fresh token (single-flighted) and stores it; null when there is no minter or
  // the mint fails, in which case the caller falls through to its normal error path.
  renew(): Promise<string | null> {
    if (!this.minter) return Promise.resolve(null);
    if (!this.inflight) {
      this.token = null;
      this.inflight = this.minter()
        .then(tok => { this.token = tok; return tok; })
        .finally(() => { this.inflight = null; });
    }
    return this.inflight;
  }
}

// ApiError carries the HTTP status and the server's optional machine-readable error code
// (e.g. "admin_key_custody") so callers can branch on the cause; err.message still holds the
// human-readable error for existing consumers.
export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export interface FetchJSONOpts {
  session?: BearerSession; // the bearer to attach and renew; none ⇒ an unauthenticated call
  token?: string;          // an explicit bearer instead of the session's — never renewed here,
                           // since the renewal hook only ever knows the active account
  mintIfMissing?: boolean; // mint before the first call when the session holds no token yet
  renew?: boolean;         // renew once on 401 and retry (default true when a session is given)
  retried?: boolean;       // internal: the single post-renewal retry
}

// fetchJSON is the JSON request every API call is: bearer attached, one transparent renewal
// and retry on 401, the server's error shape raised as ApiError, 204 as undefined.
export async function fetchJSON<T>(method: string, url: string, body?: unknown, o: FetchJSONOpts = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (o.session && o.mintIfMissing && !o.token && !o.session.get()) await o.session.renew();
  const bearer = o.token ?? o.session?.get();
  if (bearer) headers['Authorization'] = `Bearer ${bearer}`;

  const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });

  // Expired/invalid session: renew once and retry. The retry re-reads the now-fresh token. If
  // renewal cannot recover, fall through to the normal error path (the mail client's handler
  // also redirects to login).
  const mayRenew = o.session !== undefined && o.token === undefined && o.renew !== false && !o.retried && o.session.canRenew();
  if (res.status === 401 && mayRenew) {
    const fresh = await o.session!.renew();
    if (fresh) return fetchJSON<T>(method, url, body, { ...o, retried: true });
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(err.error || `HTTP ${res.status}`, res.status, err.code);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}
