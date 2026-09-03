// Runtime config rendered into index.html by the Go backend (html/template) and
// exposed as a global `env` object. Values are filled per request; in raw
// `vite dev` they remain literal "{{ .X }}" placeholders, which src/lib/config.ts
// detects and replaces with defaults.
type Env = {
  /** Per-request CSP nonce (also set on the script tag). */
  NONCE: string;
  /** Build version of the serving binary. */
  VERSION: string;
  /** Suggested domain for register/login placeholders (UX only). */
  DEFAULT_DOMAIN: string;
  /** Comma-separated domains users may register on (the backend's issuer/permit domains). */
  DOMAINS: string;
  /** "true" when the backend runs in dev mode. */
  DEV_MODE: string;
  /** Mailbox poll cadence in milliseconds (string; parsed client-side). */
  POLL_INTERVAL_MS: string;
  // Whatever else THIS deployment's backend renders. Those values are read by
  // src/deployment.tsx through config.envVal(), which tolerates an absent key — so the
  // shared client never has to know one front door's settings from another's.
  [key: string]: string | undefined;
};

declare const env: Env;

// Side-effect stylesheet imports (`import './styles/tokens.css'`) resolve to nothing at the type
// level; vite handles them at build time.
declare module '*.css';
