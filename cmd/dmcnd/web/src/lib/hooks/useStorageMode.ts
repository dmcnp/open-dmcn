// useStorageMode reports whether this session's account state (Sent, contacts, flags,
// settings) is syncing to the relay or has fallen back to this device only.
//
// It exists so the shell can SAY so. A relay that hosts no personal storage is a valid,
// supported deployment — but an account whose state silently stops following it between
// devices looks exactly like data loss from the user's side, and they find out by opening
// a second device to an empty Sent folder.
//
// The underlying flag is discovered lazily, on the first storage call that gets UNSUPPORTED
// back, so this starts false and flips once — hence the subscription rather than a plain read.

import { useEffect, useState } from 'react';
import { isStorageLocalOnly, onStorageLocalOnly } from '../api/personalStore';

export function useStorageMode(): { localOnly: boolean } {
  const [localOnly, setLocalOnly] = useState(isStorageLocalOnly);
  useEffect(() => {
    // Re-read on mount as well as subscribing: the flag may have flipped between this
    // component's initial render and the effect running.
    setLocalOnly(isStorageLocalOnly());
    return onStorageLocalOnly(setLocalOnly);
  }, []);
  return { localOnly };
}
