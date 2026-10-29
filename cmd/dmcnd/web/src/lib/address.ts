// Address-choice rules for user-chosen addresses, mirroring the Go validator in
// internal/core/identity/address_rules.go exactly. This is a client-side UX check
// only — the server (HandleRegister) re-enforces the same rules authoritatively.

// One character is a valid address (me@example.me). A deployment that holds short
// names back on a domain it shares between customers passes its own minimum.
const LOCAL_PART_MIN = 1;
const LOCAL_PART_MAX = 64;
// A 32-byte Ed25519/X25519 key hex-encodes to 64 chars; the identity fingerprint
// (first 20 bytes of SHA-256) hex-encodes to 40 chars. Either shape is reserved.
const HEX_PUBLIC_KEY_LEN = 64;
const HEX_FINGERPRINT_LEN = 40;

// Starts and ends with an alphanumeric; every separator (-._) is sandwiched between
// alphanumeric runs, so no leading/trailing/consecutive separators.
const LOCAL_PART_RE = /^[a-z0-9]+([-._][a-z0-9]+)*$/;
const HEX_ONLY_RE = /^[0-9a-f]+$/;

// validateLocalPart returns an error message if the local-part is invalid, or null
// if it is acceptable. minLength raises the shortest length allowed.
export function validateLocalPart(local: string, minLength = LOCAL_PART_MIN): string | null {
  if (local.length < minLength || local.length > LOCAL_PART_MAX) {
    return `Local part must be ${minLength}–${LOCAL_PART_MAX} characters`;
  }
  if (!LOCAL_PART_RE.test(local)) {
    return 'Local part must be lowercase, start and end with a letter or digit, use only ' +
      'a–z, 0–9, dot, dash, underscore, and not repeat dot/dash/underscore';
  }
  if ((local.length === HEX_PUBLIC_KEY_LEN || local.length === HEX_FINGERPRINT_LEN) && HEX_ONLY_RE.test(local)) {
    return 'Local part must not be a public key';
  }
  return null;
}

// validateChosenAddress splits a local@domain address and validates the local-part.
// Returns an error message or null.
export function validateChosenAddress(address: string, minLength = LOCAL_PART_MIN): string | null {
  const at = address.indexOf('@');
  if (at < 0 || at !== address.lastIndexOf('@')) {
    return 'Address must be in local@domain form';
  }
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (domain === '') {
    return 'Address must be in local@domain form';
  }
  return validateLocalPart(local, minLength);
}
