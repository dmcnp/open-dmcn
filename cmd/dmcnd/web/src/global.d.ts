// Runtime config rendered into index.html by the Go backend (html/template) and
// exposed as a global `env` object. Values are filled per request; in raw
// `vite dev` they remain literal "{{ .X }}" placeholders, which src/lib/config.ts
// detects and replaces with defaults.
type Env = {
  /** Per-request CSP nonce (also set on the script tag). */
  NONCE: string;
  /** Build version of the dmcn-web binary. */
  VERSION: string;
  /** Suggested domain for register/login placeholders (UX only). */
  DEFAULT_DOMAIN: string;
  /** Comma-separated domains users may register on (the web's issuer/permit domains). */
  DOMAINS: string;
  /** "true" when the backend runs in dev mode. */
  DEV_MODE: string;
  /** Mailbox poll cadence in milliseconds (string; parsed client-side). */
  POLL_INTERVAL_MS: string;
  /** Base URL of the account/funnel service (dmcn-b2c) the SPA sends
   *  register/countersign/billing calls to. Empty ⇒ same-origin (dev proxy). */
  ACCOUNT_URL: string;
  /** "true" on a business front door that offers no public signup. */
  REGISTRATION_CLOSED: string;
  /** Where to send would-be registrants when registration is closed here. */
  SIGNUP_URL: string;
  /** This domain's root Ed25519 public key, base64. Public: it is what the _dmcn fingerprint
   *  commits to. Used client-side to verify a bridge's credential. */
  DOMAIN_ROOT_PUB: string;
  /** "true" on a live self-hosted domain whose root key is offline: nobody can self-register,
   *  so /register becomes the petition flow (ask an admin for a mailbox). */
  PETITION_MODE: string;
};

declare const env: Env;
