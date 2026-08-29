// Light/dark + density preferences. The app shell owns the live toggles and persists
// them here; every other screen goes through these accessors so the whole app stays
// visually consistent without a global provider.
//
// These are DEVICE-local, not account-level — the counterpart of api/settingsStore.ts,
// which keeps the preferences that should follow the user (signature, compose default)
// in the personal KV instead. Device-local means per context: an installed app and a
// browser tab are separate devices to their user, so they carry separate appearance
// (see appContext.storageKey). Keep the key strings in this file only, so that stays
// true by construction.

import { storageKey } from './appContext';

export type Theme = 'light' | 'dark';
export type ThemePref = 'light' | 'dark' | 'system';

const THEME_KEY = 'dmcn_theme';
const DENSITY_KEY = 'dmcn_density';

// readThemePref returns the raw stored preference (including "system"); anything
// not explicitly light/dark means "follow the OS".
export function readThemePref(): ThemePref {
  const saved = localStorage.getItem(storageKey(THEME_KEY));
  return saved === 'light' || saved === 'dark' ? saved : 'system';
}

export function writeThemePref(pref: ThemePref): void {
  try { localStorage.setItem(storageKey(THEME_KEY), pref); } catch { /* ignore */ }
}

// resolveTheme maps a preference to the concrete theme to apply.
export function resolveTheme(pref: ThemePref): Theme {
  if (pref === 'light' || pref === 'dark') return pref;
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function readTheme(): Theme {
  return resolveTheme(readThemePref());
}

export type Density = 'compact' | 'comfortable';

export function readDensity(): Density {
  return localStorage.getItem(storageKey(DENSITY_KEY)) === 'compact' ? 'compact' : 'comfortable';
}

export function writeDensity(density: Density): void {
  try { localStorage.setItem(storageKey(DENSITY_KEY), density); } catch { /* ignore */ }
}
