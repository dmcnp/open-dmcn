import { storageKey } from './appContext';
// "Remember this address" recall — a small localStorage-backed list of email
// addresses the user has signed in with, most-recent first. Supports multiple
// stored addresses (surfaced as <datalist> suggestions on the sign-in field).
// Addresses only — never passphrases or keys.

// Per context (installed app vs tab), like every other device-local key — see appContext.
const KEY = () => storageKey('dmcn_saved_emails');
const MAX = 8;

export function getSavedEmails(): string[] {
  try {
    const raw = localStorage.getItem(KEY());
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr.filter((e): e is string => typeof e === 'string') : [];
  } catch {
    return [];
  }
}

export function addSavedEmail(email: string): void {
  const e = email.trim();
  if (!e) return;
  const next = [e, ...getSavedEmails().filter(x => x.toLowerCase() !== e.toLowerCase())].slice(0, MAX);
  try { localStorage.setItem(KEY(), JSON.stringify(next)); } catch { /* ignore */ }
}

export function removeSavedEmail(email: string): void {
  const e = email.trim().toLowerCase();
  const next = getSavedEmails().filter(x => x.toLowerCase() !== e);
  try { localStorage.setItem(KEY(), JSON.stringify(next)); } catch { /* ignore */ }
}
