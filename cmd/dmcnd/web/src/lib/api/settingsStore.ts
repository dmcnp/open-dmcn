// SettingsStore holds ACCOUNT-level preferences that should follow the user across
// devices — display name, composing signature — in a single sealed "settings/app"
// document. (Device-local prefs like theme, density and "stay signed in" deliberately
// stay in localStorage; they are per-device by nature.) Low-churn singleton, so it
// uses compare-and-swap via the store's version token (the provider retries on conflict).

import { PersonalStore } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';

export interface AppSettings {
  v: number;
  displayName?: string;
  signature?: string;
  // Overrides the system default (rich text) for NEW messages and replies. Only ever
  // seeds the composer's starting mode — the per-message toggle still wins. Left
  // undefined for every existing account, which reads as "use the default".
  composePlainText?: boolean;
}

export const SETTINGS_KEY = 'settings/app';

export function emptySettings(): AppSettings {
  return { v: 1 };
}

export class SettingsStore {
  private store: PersonalStore;

  constructor(keys: WorkingKeys) {
    this.store = new PersonalStore(keys);
  }

  async get(): Promise<{ settings: AppSettings; version: number }> {
    const e = await this.store.get<AppSettings>(SETTINGS_KEY);
    if (!e) return { settings: emptySettings(), version: 0 };
    return { settings: { ...emptySettings(), ...e.value, v: 1 }, version: e.version };
  }

  put(settings: AppSettings, expectedVersion: number): Promise<number> {
    return this.store.put(SETTINGS_KEY, settings, expectedVersion);
  }
}
