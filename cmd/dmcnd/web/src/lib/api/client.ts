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
  token?: string; // explicit bearer, bypassing the module token (see logoutToken)
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
  const bearer = opts.token ?? sessionToken;
  if (bearer) {
    headers['Authorization'] = `Bearer ${bearer}`;
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

// postJSONAs is the same POST under an EXPLICIT bearer when one is given, falling
// back to the global session when it isn't. Used by the sessions that aren't the
// tab's current account. Explicit tokens skip session renewal: the renewal handler
// only ever knows the active account, so a 401 here is the caller's to re-mint.
export function postJSONAs<T>(token: string | undefined, path: string, body: unknown): Promise<T> {
  return token === undefined ? postJSON<T>(path, body) : request<T>('POST', path, body, { token, skipReauth: true });
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

// --- Mailbox petitions (live self-hosted domains) ----------------------------------------
//
// On a domain whose root key is kept offline the node cannot mint an address, so there is no
// self-service registration. Instead the browser proves it holds a fresh keypair, gets a
// 12-digit code, and the person reads that code to their admin out of band. The admin assigns an
// address with the offline root; the browser learns it by polling and then self-signs a record
// for it. The petitioner never chooses their own address — that is what makes an unclaimed
// petition worthless and lets it simply expire.

export interface PetitionRequest {
  ed25519_pub: string;
  x25519_pub: string;
  proof: string; // Ed25519 over "dmcn-petition-v1\0" ‖ ed25519_pub ‖ x25519_pub
}

export interface PetitionResponse {
  code: string;       // "0428-9173-5560"
  expires_at: string; // RFC3339
}

export function createPetition(req: PetitionRequest): Promise<PetitionResponse> {
  return request('POST', '/api/v1/petition', req, { skipReauth: true });
}

export interface PetitionStatusResponse {
  status: 'pending' | 'assigned';
  address?: string;    // set once assigned
  expires_at?: string; // set while pending
}

export function petitionStatus(code: string): Promise<PetitionStatusResponse> {
  return request('GET', `/api/v1/petition/status?code=${encodeURIComponent(code)}`, undefined, { skipReauth: true });
}

export interface PetitionCompleteRequest {
  code: string;
  identity_record: string; // base64 proto, self-signed for the ASSIGNED address
}

export function completePetition(req: PetitionCompleteRequest): Promise<RegisterResponse & { address?: string }> {
  return request('POST', '/api/v1/petition/complete', req, { skipReauth: true });
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

// logoutToken revokes ONE session token explicitly, rather than whichever the module holds.
// The account switcher installs the incoming session first and then ends the outgoing one
// with this: revoking via the module token would either race the switch or (on a 401)
// re-enter session renewal for the account being left. Server-side logout is per-token, so
// this cannot disturb another tab.
export function logoutToken(token: string): Promise<void> {
  return request('POST', '/api/v1/logout', undefined, { skipReauth: true, token });
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
  // NOTE: there is deliberately no bridge_capability here. A bridge has no email address and no
  // directory entry — its verdicts are verified against a root-signed credential carried in the
  // message itself (lib/crypto/bridgeAttest.ts), never by a flag the server controls.
  // Effective onion-delivery policy (mailbox flag OR domain DAR). When true, the
  // compose UI auto-enables + locks the onion toggle; the server enforces it too.
  require_onion?: boolean;
  // True when the address's domain declares admin key custody (DAR policy): the domain admin
  // holds the account keys. A single-domain daemon has no such policy to report, so this is
  // never set here — it is declared because the pinned-fact set is shared, and a contact whose
  // domain turns custody ON is a change no key comparison can see (trust/pinnedKey.ts).
  admin_key_custody?: boolean;
  // legacy marks a recipient that is NOT a DMCN identity — an ordinary email address, reachable
  // through this domain's SMTP bridge. When true, x25519_pub and relay_hints describe the BRIDGE,
  // not the recipient: the message is end-to-end encrypted as far as the bridge and travels as
  // ordinary email from there. There is no ed25519_pub, because there is no identity behind it.
  legacy?: boolean;
  relay_hints?: string[];
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
