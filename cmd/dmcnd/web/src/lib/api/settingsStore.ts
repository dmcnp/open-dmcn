// SettingsStore holds ACCOUNT-level preferences that should follow the user across
// devices — the composing signature and defaults — in a single sealed "settings/app"
// document. (Device-local prefs like theme, density and "stay signed in" deliberately
// stay in localStorage; they are per-device by nature — and "device" includes an
// installed app separately from the browser tab that installed it, so those keys are
// namespaced per context. See lib/appContext.ts.) Anything that should genuinely look
// the same everywhere belongs HERE, where it is account data rather than something
// leaking between two contexts. Low-churn singleton, so it uses compare-and-swap via
// the store's version token (the provider retries on conflict).

import { PersonalStore } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';

export interface AppSettings {
  v: number;
  // Deprecated: the app labels the signed-in account by its ADDRESS (which is what
  // the mesh routes to and what tells two open accounts apart), and labels OTHER
  // people by the name their owner gave them in Contacts. Kept only so a document
  // written by an older client still round-trips.
  displayName?: string;
  signature?: string;
  // Overrides the system default (rich text) for NEW messages and replies. Only ever
  // seeds the composer's starting mode — the per-message toggle still wins. Left
  // undefined for every existing account, which reads as "use the default".
  composePlainText?: boolean;
  // Opt in to fetching images from the sender's own server, for senders on the allowlist
  // only. Undefined/false — the default, and what every existing account reads as — keeps
  // remote images blocked everywhere. It lives HERE rather than in localStorage because it
  // is a decision about correspondents, which is account data: a device that has never seen
  // this setting should not quietly re-block a sender the owner already decided about.
  remoteImagesForTrusted?: boolean;
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
