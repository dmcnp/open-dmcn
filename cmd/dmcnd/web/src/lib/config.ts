// Runtime configuration read from the global `env` object that the Go backend
// renders into index.html (see internal/server spaHandler + index.html template).
// This lets one embedded build be configured per deploy without rebuilding the
// frontend. Only non-secret, deploy-specific values are present.
//
// In raw `vite dev` the Go template isn't applied, so values are the literal
// "{{ .X }}" placeholders — envVal() detects those (and a missing `env`) and falls
// back to the defaults below, so the app works the same in dev.

// envVal reads one rendered value. Exported because src/deployment.tsx reads the keys
// that belong to ITS front door rather than to the mail client, and those keys differ
// per deployment — an absent one simply falls back.
export function envVal(key: string, fallback: string): string {
  const v = typeof env !== 'undefined' ? env[key] : undefined;
  if (typeof v !== 'string' || v === '' || v.startsWith('{')) return fallback;
  return v;
}

/** Build version of the backend, or "dev" when unset/unrendered. */
export const APP_VERSION = envVal('VERSION', 'dev');
/** Per-request CSP nonce (empty in dev). */
export const NONCE = envVal('NONCE', '');
/** The mail domain this deployment serves, derived from the browser's host, with
 *  any leading front-door subdomain (www/app/mail/get) stripped to the apex. Used
 *  ONLY to build illustrative placeholders (e.g. a compose recipient hint); it is
 *  never a value forced into an input. Empty outside a browser (SSR/tests). */
function hostDomain(): string {
  if (typeof window === 'undefined') return '';
  return window.location.hostname.replace(/^(www|app|mail|get)\./, '');
}
/** Domain used only to build example placeholders like `name@<domain>` in
 *  free-text recipient fields. Precedence: DMCN_WEB_DEFAULT_DOMAIN (explicit) >
 *  the serving host. This is placeholder text, not a selected/forced value. */
export const DEFAULT_DOMAIN = envVal('DEFAULT_DOMAIN', '') || hostDomain();
/** Domains the register/pair address field offers as a picker, rendered by the
 *  backend from its issuer/permit domains (env.DOMAINS, comma-separated). EMPTY
 *  when the deploy configures none — the address field then lets the user type
 *  the domain freely (an unconfigured instance imposes no default domain, which
 *  matters for pairing an account that may live on any domain). One domain ⇒ a
 *  fixed suffix; several ⇒ a dropdown. */
export const DOMAINS: string[] = (() => {
  const raw = envVal('DOMAINS', '');
  const list = raw.split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
  return [...new Set(list)];
})();
/** True when the backend reports dev mode. */
export const IS_DEV = envVal('DEV_MODE', '') === 'true';
/** Mailbox (inbox) poll cadence (ms). Defaults to 10s when unset/unrendered. New
 *  mail arrives externally, so the inbox is the one thing that needs frequent polling. */
export const POLL_INTERVAL_MS = Number(envVal('POLL_INTERVAL_MS', '10000')) || 10000;
/** Personal-store poll cadence (ms) for low-churn owner data (Sent, flags, contacts).
 *  These change on local action (updated optimistically) or, rarely, from another
 *  device — so they poll far less often than the inbox to avoid a per-tick request
 *  burst. Definitions (labels/settings) don't poll on a timer at all; they refresh on
 *  tab focus. Derived as 6× the inbox cadence (min 60s), so it stays well clear of the
 *  inbox poll even if an operator retunes POLL_INTERVAL_MS. */
export const STORAGE_POLL_INTERVAL_MS = Math.max(60_000, POLL_INTERVAL_MS * 6);
