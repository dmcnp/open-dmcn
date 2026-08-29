// This deployment's block/allow list: device-local, in IndexedDB.
//
// The relay-held form the product uses is an operator surface the open protocol does not
// carry, so the list here is advisory — it drives the client-side trust view, and blocked
// mail still arrives, it just isn't shown. Everything else about it is the same; see
// lib/api/filterList.ts for the shared shape and lib/deployment.ts for the seam.

import { idbGet, idbPut, idbDelete, PERSONAL_STORE } from '../../../src/lib/crypto/idb';
import type { WorkingKeys } from '../../../src/lib/crypto/workingKeys';

export type { FilterList } from '../../../src/lib/api/filterList';
import type { FilterList, MailFilter } from '../../../src/lib/api/filterList';

// The single logical key the filter list is stored under, per account.
const FILTER_KEY = 'filter/list';

export class MailFilterClient implements MailFilter {
  // The owner address namespaces the list within the shared per-origin store.
  private owner: string;

  // explicitToken is accepted to satisfy MailFilterFactory and deliberately ignored: this
  // list never leaves the device, so there is no session for it to be read under.
  constructor(keys: WorkingKeys, _explicitToken?: string) {
    this.owner = keys.address;
  }

  private key(): string {
    return this.owner + '::' + FILTER_KEY;
  }

  // get returns the current filter list, or null if none set.
  async get(): Promise<FilterList | null> {
    const list = await idbGet<FilterList>(PERSONAL_STORE, this.key());
    return list ?? null;
  }

  // save stores the list locally.
  async save(list: FilterList): Promise<void> {
    await idbPut(PERSONAL_STORE, this.key(), list);
  }

  // clear removes the filter (revert to allow-everything).
  async clear(): Promise<void> {
    await idbDelete(PERSONAL_STORE, this.key());
  }
}
