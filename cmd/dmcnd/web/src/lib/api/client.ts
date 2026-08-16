import { signWithKey } from '../crypto/sign';
import { fromBase64, toBase64 } from '../crypto/keys';

let sessionToken: string | null = null;

export function setSessionToken(token: string | null) {
  sessionToken = token;
}

export function getSessionToken(): string | null {
  return sessionToken;
}

// Session-renewal hook. The app registers a handler (see SessionRenewer) that
// re-mints the JWT from the in-memory key when a request comes back 401. Renewal
// is single-flighted so a burst of concurrent 401s (e.g. the mailbox poll plus
// another call) triggers exactly one renewal.
let reauthHandler: (() => Promise<string | null>) | null = null;
let reauthInflight: Promise<string | null> | null = null;

export function setReauthHandler(fn: (() => Promise<string | null>) | null) {
  reauthHandler = fn;
}

function runReauth(): Promise<string | null> {
  if (!reauthHandler) return Promise.resolve(null);
  if (!reauthInflight) {
    reauthInflight = reauthHandler().finally(() => {
      reauthInflight = null;
    });
  }
  return reauthInflight;
}

interface RequestOpts {
  retried?: boolean; // internal: set on the single post-renewal retry
  skipReauth?: boolean; // public/auth endpoints opt out (no session to renew)
}

// ApiError carries the HTTP status and the server's optional machine-readable
// error code so callers can branch on the cause;
// err.message still holds the human-readable error for existing consumers.
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

async function request<T>(method: string, path: string, body?: unknown, opts: RequestOpts = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (sessionToken) {
    headers['Authorization'] = `Bearer ${sessionToken}`;
  }

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  // Expired/invalid session: transparently renew the token once and retry. The
  // retry re-reads the now-fresh module token. If renewal can't recover, fall
  // through to the normal error path (the handler also redirects to login).
  if (res.status === 401 && !opts.retried && !opts.skipReauth && reauthHandler) {
    const fresh = await runReauth();
    if (fresh) {
      return request<T>(method, path, body, { ...opts, retried: true });
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(err.error || `HTTP ${res.status}`, res.status, err.code);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

// Generic authenticated POST on the global session that participates in session
// renewal — for callers outside the typed wrappers (e.g. the mailbox sync).
export function postJSON<T>(path: string, body: unknown): Promise<T> {
  return request('POST', path, body);
}

// Auth API. The server holds no key material — it is a public-key directory (the
// fleet-resolved registry record). Login/import carry public material and
// challenge-response proofs; the encrypted keystore lives client-side (localKeystore).
export interface LoginResponse {
  ed25519_pub: string;
  challenge_nonce: string;
}

export interface SessionResponse {
  session_token: string;
}

// Import API (prove possession of an existing identity on this device). The blob is
// stored locally by the caller, never sent here.
export interface ImportChallengeResponse {
  ed25519_pub: string;
  x25519_pub: string;
  challenge_nonce: string;
}

export interface ImportRequest {
  address: string;
  challenge_nonce: string;
  challenge_signature: string;
}

export function importChallenge(address: string): Promise<ImportChallengeResponse> {
  return request('POST', '/api/v1/import/challenge', { address }, { skipReauth: true });
}

export function importIdentity(req: ImportRequest): Promise<SessionResponse> {
  return request('POST', '/api/v1/import', req, { skipReauth: true });
}

// Self-service registration against the local daemon (it is the operator for its own
// domain). The browser generates the keys and self-signs the record; the server attaches a
// routing credential and publishes it. Mints NO session — after "active" the caller logs in
// with the fresh keys (loginWithKeys).
export interface RegisterRequest {
  address: string;
  ed25519_pub: string;
  x25519_pub: string;
  identity_record: string;
  self_signature: string;
}

export interface RegisterResponse {
  status?: string; // "active"
}

export function register(req: RegisterRequest): Promise<RegisterResponse> {
  return request('POST', '/api/v1/register', req, { skipReauth: true });
}

export function login(address: string): Promise<LoginResponse> {
  return request('POST', '/api/v1/login', { address }, { skipReauth: true });
}

export function loginVerify(address: string, challengeSignature: string, challengeNonce: string): Promise<SessionResponse> {
  return request('POST', '/api/v1/login/verify', {
    address,
    challenge_signature: challengeSignature,
    challenge_nonce: challengeNonce,
  }, { skipReauth: true });
}

// Sign a login challenge nonce with an already-unlocked working key handle and
// exchange it for a session token. Shared by the Login page and silent renewal.
export async function verifyChallenge(address: string, signKey: CryptoKey, challengeNonce: string): Promise<string> {
  const signature = await signWithKey(signKey, fromBase64(challengeNonce));
  const { session_token } = await loginVerify(address, toBase64(signature), challengeNonce);
  return session_token;
}

// Full silent re-login from an unlocked working key (fetches a fresh challenge
// first). No passphrase needed — the key is already unlocked.
export async function loginWithKeys(address: string, signKey: CryptoKey): Promise<string> {
  const resp = await login(address);
  return verifyChallenge(address, signKey, resp.challenge_nonce);
}

export function logout(): Promise<void> {
  return request('POST', '/api/v1/logout');
}

// Identity API
export interface IdentityLookupResponse {
  address: string;
  ed25519_pub: string;
  x25519_pub: string;
  fingerprint: string;
  verification_tier: number;
  // verified_tier is the cryptographically verified tier (DAR + DNS + removal
  // checked), vs the self-claimed verification_tier. identity_unverifiable is
  // true when the record CLAIMED a countersignature that failed to verify
  // (revoked binding / unauthorized countersigner) — distrust such identities.
  verified_tier?: number;
  identity_unverifiable?: boolean;
  // True when this address is a registered SMTP bridge. Used to verify a bridged
  // message's classification attestation (see crypto/bridgeAttest.ts).
  bridge_capability?: boolean;
  // Effective onion-delivery policy (mailbox flag OR domain DAR). When true, the
  // compose UI auto-enables + locks the onion toggle; the server enforces it too.
  require_onion?: boolean;
  // True when the address's domain declares admin key custody (DAR policy): the
  // domain admin holds the account keys — shown as the managed-account badge.
}

export function lookupIdentity(address: string): Promise<IdentityLookupResponse> {
  return request('GET', `/api/v1/identity/lookup?address=${encodeURIComponent(address)}`);
}

// Relay hints API
export interface RelayHintsResponse {
  relay_hints: string[];
}

// Load-aware mailbox relay hints for an address (its domain's mailbox relays, ranked).
// Rejects with a 503 when the domain has no reachable mailbox relay.
export function getRelayHints(address: string): Promise<RelayHintsResponse> {
  return request('GET', `/api/v1/relay-hints?address=${encodeURIComponent(address)}`);
}

// Messages API
export interface SendMessageRequest {
  sender_address: string;
  sender_signature: string;
  envelope: string;
  recipient_address: string;
  /** Request 3-hop onion-routed delivery. The server also forces it when the
   *  recipient's record requires onion (stricter-wins). */
  onion?: boolean;
}

export interface SendMessageResponse {
  envelope_hash: string;
}

export function sendMessage(req: SendMessageRequest): Promise<SendMessageResponse> {
  return request('POST', '/api/v1/messages/send', req);
}
