// LabelStore holds the user's label + folder DEFINITIONS in a single settings
// document ("settings/labels") in the personal store, sealed to the owner. This is
// a low-churn singleton, so it uses compare-and-swap (the store's version token) to
// avoid lost updates when two devices edit definitions at once — the provider
// re-reads and retries on conflict. Per-message assignment lives in the flag records
// (folderId / labelIds); this doc only names the labels/folders and gives colors.
// The order of each array is the order the rail and the pickers list them in, which the owner
// sets in Settings; the Apple client reads and writes the same order.

import { PersonalStore } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';

export interface LabelDef {
  id: string;
  name: string;
  color: string; // CSS color for the swatch
}

export interface FolderDef {
  id: string;
  name: string;
}

export interface LabelsDoc {
  v: number;
  labels: LabelDef[];
  folders: FolderDef[];
}

export const LABELS_KEY = 'settings/labels';

export function emptyLabelsDoc(): LabelsDoc {
  return { v: 1, labels: [], folders: [] };
}

export class LabelStore {
  private store: PersonalStore;

  constructor(keys: WorkingKeys, explicitToken?: string) {
    this.store = new PersonalStore(keys, explicitToken);
  }

  // get returns the definitions doc + its version (0 when none exists yet).
  async get(): Promise<{ doc: LabelsDoc; version: number }> {
    const e = await this.store.get<LabelsDoc>(LABELS_KEY);
    if (!e) return { doc: emptyLabelsDoc(), version: 0 };
    return {
      doc: { v: 1, labels: e.value.labels ?? [], folders: e.value.folders ?? [] },
      version: e.version,
    };
  }

  // put writes the doc with compare-and-swap on expectedVersion (throws
  // StorageConflictError on mismatch — the caller re-reads and retries).
  put(doc: LabelsDoc, expectedVersion: number): Promise<number> {
    return this.store.put(LABELS_KEY, doc, expectedVersion);
  }
}
