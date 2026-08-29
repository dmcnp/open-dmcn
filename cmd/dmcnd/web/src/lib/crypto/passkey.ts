// Passkey-based keystore unlock via the WebAuthn PRF extension (CTAP2 hmac-secret).
//
// Standard WebAuthn only authenticates; the PRF extension additionally returns a
// stable, high-entropy 32-byte secret per (credential, salt) that never leaves the
// authenticator. We HKDF that secret into an AES-GCM key and use it to encrypt the
// keystore blob — so only this passkey can decrypt the identity keys. The server
// never sees the secret and performs no WebAuthn ceremony (login still proves
// possession of the DMCN key); the passkey purely gates local decryption.

import { toBase64, fromBase64 } from './keys';
import { isInstalledApp } from '../appContext';

const PRF_INFO = new TextEncoder().encode('dmcn-webkeys-prf-v1');

// Not every passkey provider implements the PRF extension (hmac-secret) this scheme
// derives its key from. Third-party password managers (e.g. NordPass) commonly don't,
// and neither does Chrome's own profile-bound Touch ID store on macOS — which is the
// one a Chrome-installed app tends to get, where a browser tab gets the system
// provider instead. Both messages below therefore name the provider as the problem
// and give somewhere else to go, rather than blaming the user's choice.

// At UNLOCK: a credential answered but returned no PRF secret, so it cannot derive
// this account's key.
function prfUnsupportedAtUnlockMessage(): string {
  return (
    'the passkey that answered can’t unlock this account — it doesn’t support the PRF extension ' +
    'DMCN derives the key from. ' +
    (isInstalledApp()
      ? 'Set this account up here with a password instead.'
      : 'Use the device passkey you enrolled for this account, or import your backup.')
  );
}

// The same failure at ENROLLMENT, where we know more and can say more. A passkey was
// created and is useless — so name the provider problem rather than telling the user
// to use the built-in passkey they just used, and say the credential can be deleted.
function prfUnsupportedAtEnrollmentMessage(): string {
  return (
    'the passkey that was created can’t protect your keys — the authenticator that answered ' +
    'doesn’t support the PRF extension DMCN needs, so that passkey is unusable and can be deleted. ' +
    (isInstalledApp()
      ? 'Use a password for this app instead.'
      : 'Choose a password instead, or try your device’s built-in passkey rather than a password-manager extension.')
  );
}

// Cancelled, or the local authenticator had no passkey to offer — WebAuthn reports
// NotAllowedError for both, so the message has to carry both.
const PASSKEY_UNAVAILABLE_MSG = 'passkey unlock was cancelled, or this device had no passkey for this account.';

// The same failure inside an installed app, where a passkey enrolled elsewhere is
// often simply not reachable: the app doesn't always get the same platform
// authenticator a browser tab does. It keeps its own keys, so the fix is local.
const PASSKEY_UNAVAILABLE_APP_MSG =
  'this app can’t reach that passkey. Set the account up here with a password instead.';

// isPasskeySupported is a coarse capability gate (WebAuthn present + secure
// context). True PRF support can only be confirmed by attempting an enrollment,
// so createPasskeyPRF throws if the authenticator lacks PRF and the UI falls back
// to a password.
export function isPasskeySupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    !!window.PublicKeyCredential &&
    !!navigator.credentials &&
    window.isSecureContext
  );
}

async function aesKeyFromPRF(secret: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: PRF_INFO },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function isNotAllowed(e: unknown): boolean {
  return e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError');
}

// evalPRF performs an assertion against an existing credential and returns the
// PRF output for the given salt (undefined if the authenticator declined PRF).
//
// The request is deliberately confined to the LOCAL platform authenticator, and
// never widened when it comes up empty:
//
//   - transports: ['internal'] — DMCN only ever mints platform (built-in) passkeys
//     (authenticatorAttachment: 'platform' in createPasskeyPRF), and this hint tells
//     the browser the credential lives on this device. `hints: ['client-device']`
//     says the same thing in the newer WebAuthn vocabulary; clients that don't know
//     it ignore the member.
//   - Without those, a client that can't find the credential locally offers the
//     cross-device QR flow instead. That is a dead end here, not a fallback: it
//     hands the ceremony to whatever passkey provider the scanning phone happens to
//     have, and those (NordPass, 1Password, …) generally lack the PRF extension that
//     is the entire point of the ceremony — so it either hangs on the hybrid
//     connection or completes and still can't decrypt anything.
//
// So when the local authenticator has nothing to offer, the honest outcome is a
// clear failure and a route the user can actually take (see the two
// PASSKEY_UNAVAILABLE_* messages), not a QR code that cannot work.
async function evalPRF(credentialId: Uint8Array, prfSalt: Uint8Array): Promise<ArrayBuffer | undefined> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId, transports: ['internal'] }],
      hints: ['client-device'],
      userVerification: 'required',
      extensions: { prf: { eval: { first: prfSalt } } },
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  if (!assertion) return undefined;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ext = assertion.getClientExtensionResults() as any;
  return ext?.prf?.results?.first as ArrayBuffer | undefined;
}

export interface PasskeyEnrollment {
  credentialId: string; // base64
  prfSalt: string; // base64
  aesKey: CryptoKey;
}

// createPasskeyPRF enrolls a new passkey for the address and returns the derived
// AES key plus the credential id + PRF salt to persist. Throws if the platform
// doesn't support PRF (caller should fall back to a password).
export async function createPasskeyPRF(address: string): Promise<PasskeyEnrollment> {
  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  // A FRESH RANDOM user handle per enrollment — deliberately NOT the address. WebAuthn
  // deletes ("evicts") an existing discoverable credential only when a new one is
  // created for the same (rpId, user.id) pair. Platform authenticators — iCloud
  // Keychain especially — create discoverable passkeys even when we request
  // residentKey: 'discouraged', so keying user.id to the address made every
  // re-enrollment collide: importing a passkey backup wraps the local keystore under a
  // new passkey, which silently deleted the credential the backup file itself
  // references, leaving that file un-reimportable. A unique handle removes the
  // collision so credentials coexist instead of overwriting each other. DMCN never
  // uses the handle (it always supplies the credential id via allowCredentials and
  // persists only credentialId/prfSalt); the address stays the human-visible name.
  const userHandle = crypto.getRandomValues(new Uint8Array(16));
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: 'DMCN', id: location.hostname },
      user: {
        id: userHandle,
        name: address,
        displayName: address,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      // Restrict to the device's built-in authenticator (Touch ID / Windows Hello /
      // Android / iCloud Keychain). Apple/Google platform passkeys still sync, so a
      // passkey-protected backup stays portable. Roaming security keys and the
      // cross-device phone flow are excluded by design — the password path covers
      // anyone who needs those. `hints: ['client-device']` says the same thing in the
      // newer WebAuthn vocabulary; clients that don't know the member ignore it.
      //
      // residentKey: 'discouraged' asks for a non-discoverable (server-side) credential.
      // DMCN always supplies the credential id via allowCredentials, so it never needs
      // discoverability. This is only a hint — platform authenticators (iCloud Keychain
      // especially) create discoverable passkeys regardless — so it is the unique user
      // handle above, NOT this flag, that stops a re-enrollment from evicting an
      // existing credential. The flag keeps the OS passkey list uncluttered on
      // authenticators that honor it.
      //
      // 'required' was tried on the theory that asking for a real (discoverable)
      // passkey would steer Chrome on macOS away from its profile-bound Touch ID store
      // — which announces itself with "this passkey will only be saved on this device"
      // and does not implement PRF — toward the system provider, which does. It made no
      // difference: an installed Chrome app gets the profile-bound authenticator either
      // way, because reaching the system provider needs a per-application permission
      // the app bundle doesn't hold. Which authenticator answers is not ours to choose.
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'discouraged',
        userVerification: 'required',
      },
      hints: ['client-device'],
      // Evaluate PRF during creation. A platform authenticator on a current browser
      // returns the result in this same ceremony, so no second prompt is needed; the
      // assertion below covers the ones that only evaluate at assert time.
      //
      // Enabling without evaluating (`prf: {}`) was tried as a fix for Chrome's
      // profile-bound macOS authenticator refusing PRF, on the theory it might reject
      // the whole extension rather than just the optional convenience. It changed
      // nothing there — it reports prf.enabled: false either way — and it costs the
      // working path a second prompt at every enrollment, so it isn't worth keeping.
      extensions: { prf: { eval: { first: prfSalt } } },
    } as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('passkey creation was cancelled');

  const credentialId = new Uint8Array(cred.rawId);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ext = cred.getClientExtensionResults() as any;
  // The secret comes from the assertion below, since creation only enabled PRF. A
  // client that volunteered a result anyway is still honoured — `enabled` is advisory
  // and unreliable, so we gate on the actual result, never on it.
  let secret: ArrayBuffer | undefined = ext?.prf?.results?.first;
  if (!secret) {
    secret = await evalPRF(credentialId, prfSalt);
  }
  if (!secret) {
    // eslint-disable-next-line no-console
    console.warn('[passkey] PRF unavailable for this authenticator', {
      prfEnabledAtCreate: ext?.prf?.enabled,
      // Which authenticator actually answered — the useful half of a bug report.
      authenticatorAttachment: (cred as unknown as { authenticatorAttachment?: string }).authenticatorAttachment,
      installedApp: isInstalledApp(),
    });
    throw new Error(prfUnsupportedAtEnrollmentMessage());
  }

  return {
    credentialId: toBase64(credentialId),
    prfSalt: toBase64(prfSalt),
    aesKey: await aesKeyFromPRF(new Uint8Array(secret)),
  };
}

// unlockPasskeyPRF re-derives the AES key on login via an assertion against the
// stored credential + PRF salt.
export async function unlockPasskeyPRF(credentialIdB64: string, prfSaltB64: string): Promise<CryptoKey> {
  let secret: ArrayBuffer | undefined;
  try {
    secret = await evalPRF(fromBase64(credentialIdB64), fromBase64(prfSaltB64));
  } catch (e) {
    // WebAuthn deliberately reports "you declined" and "there was nothing to offer
    // you" as the same error, so the message has to carry both — and name the way
    // out, since a passkey that can't be reached here is otherwise a dead end.
    if (isNotAllowed(e)) {
      throw new Error(isInstalledApp() ? PASSKEY_UNAVAILABLE_APP_MSG : PASSKEY_UNAVAILABLE_MSG);
    }
    throw e;
  }
  if (!secret) {
    throw new Error(prfUnsupportedAtUnlockMessage());
  }
  return aesKeyFromPRF(new Uint8Array(secret));
}
