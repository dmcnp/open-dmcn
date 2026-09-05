import { signWithKey } from '../crypto/sign';
import { fromBase64, toBase64 } from '../crypto/keys';
import { ApiError, BearerSession, fetchJSON } from './bearer';

export { ApiError };

// The mail client's own session: a JWT the server mints from a challenge signed with the
// in-memory key. SessionRenewer installs the renewal hook (setReauthHandler) that re-mints it
// when a request comes back 401; see BearerSession for the single-flight semantics.
const session = new BearerSession();

export function setSessionToken(token: string | null) {
  session.set(token);
}

export function getSessionToken(): string | null {
  return session.get();
}

export function setReauthHandler(fn: (() => Promise<string | null>) | null) {
  session.setMinter(fn);
}

interface RequestOpts {
  skipReauth?: boolean; // public/auth endpoints opt out (no session to renew)
  token?: string; // explicit bearer, bypassing the module token (see logoutToken)
}

function request<T>(method: string, path: string, body?: unknown, opts: RequestOpts = {}): Promise<T> {
  return fetchJSON<T>(method, path, body, { session, token: opts.token, renew: !opts.skipReauth });
}

// Generic authenticated POST on the global session that participates in session
// renewal — for callers outside the typed wrappers (e.g. the mailbox sync).
// apiRequest is the low-level authenticated call, exported so a deployment's own endpoints
// (its account service, its bridge plane, its petition flow) share this module's session
// handling and error shape instead of re-implementing them. The shared client itself uses the
// typed wrappers below; nothing here knows which endpoints a particular deployment has.
export function apiRequest<T>(method: string, path: string, body?: unknown, opts: { skipReauth?: boolean; token?: string } = {}): Promise<T> {
  return request<T>(method, path, body, opts);
}

export function postJSON<T>(path: string, body: unknown): Promise<T> {
  return request('POST', path, body);
}

// postJSONAs is the same POST under an EXPLICIT bearer when one is given, falling
// back to the global session when it isn't. Used by the sessions that aren't the
// tab's current account — the short-lived pairing session, and the background reads
// that count another unlocked account's unread mail. Explicit tokens skip session
// renewal: the renewal handler only ever knows the active account, so a 401 here is
// the caller's to re-mint.
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

// The signed challenge is enough: the server holds the pending nonce per address and verifies
// the signature over that, so the nonce is never sent back.
export interface ImportRequest {
  address: string;
  challenge_signature: string;
}

export function importChallenge(address: string): Promise<ImportChallengeResponse> {
  return request('POST', '/api/v1/import/challenge', { address }, { skipReauth: true });
}

export function importIdentity(req: ImportRequest): Promise<SessionResponse> {
  return request('POST', '/api/v1/import', req, { skipReauth: true });
}

export function login(address: string): Promise<LoginResponse> {
  return request('POST', '/api/v1/login', { address }, { skipReauth: true });
}

export function loginVerify(address: string, challengeSignature: string): Promise<SessionResponse> {
  return request('POST', '/api/v1/login/verify', {
    address,
    challenge_signature: challengeSignature,
  }, { skipReauth: true });
}

// Sign a login challenge nonce with an already-unlocked working key handle and
// exchange it for a session token. Shared by the Login page and silent renewal.
export async function verifyChallenge(address: string, signKey: CryptoKey, challengeNonce: string): Promise<string> {
  const signature = await signWithKey(signKey, fromBase64(challengeNonce));
  const { session_token } = await loginVerify(address, toBase64(signature));
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
  // Effective onion-delivery policy (mailbox flag OR domain DAR). When true, the
  // compose UI auto-enables + locks the onion toggle; the server enforces it too.
  require_onion?: boolean;
  // legacy marks a recipient that is NOT a DMCN identity — an ordinary email address, reachable
  // through this domain's SMTP bridge. When true, x25519_pub and relay_hints describe the BRIDGE,
  // not the recipient: the message is end-to-end encrypted as far as the bridge and travels as
  // ordinary email from there. There is no ed25519_pub, because there is no identity behind it.
  //
  // This backend answers a legacy address with 404 instead, so the field is never set here. It is
  // declared because the trust code is shared with a deployment whose directory does answer this
  // way, and because the alternative — falling through to the key comparison with no key to
  // compare — reports ordinary bridged mail as an impersonation attempt.
  legacy?: boolean;
  // Where to STORE for this address. On a legacy answer these describe the BRIDGE.
  relay_hints?: string[];
  // True when the address's domain declares admin key custody (DAR policy): the
  // domain admin holds the account keys — shown as the managed-account badge.
  admin_key_custody?: boolean;
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
  /** Hex of the per-compose messageId, identical across the one POST made per
   *  recipient. Send-cap enforcement counts a multi-recipient compose as one
   *  message but N recipients; empty ⇒ each POST is its own message. */
  message_id?: string;
}

export interface SendMessageResponse {
  envelope_hash: string;
}

export function sendMessage(req: SendMessageRequest): Promise<SendMessageResponse> {
  return request('POST', '/api/v1/messages/send', req);
}
