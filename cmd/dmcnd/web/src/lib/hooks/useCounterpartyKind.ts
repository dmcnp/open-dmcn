// useCounterpartyKind resolves the DMCN-vs-legacy kind of the person a mail row is
// about (its sender, or its recipient in Sent). Contacts answer instantly from local
// data; anyone else needs the directory, which is fetched once per address per
// session (see senderKind.ts) and reported as 'unknown' until it lands, so a row
// never renders a claim it can't back.

import { useEffect, useState } from 'react';
import { lookupIdentity } from '../api/client';
import { useContacts } from './useContacts';
import { contactKind, directoryKey, kindFromDirectory, type SenderKind } from '../trust/senderKind';

export function useCounterpartyKind(address: string, messageKeyHex = ''): SenderKind {
  const { contactByAddress } = useContacts();
  const local = contactKind(contactByAddress(address));
  const [resolved, setResolved] = useState<SenderKind>('unknown');

  useEffect(() => {
    // A contact already answered it; don't ask the directory.
    if (local !== 'unknown' || !address) return;
    let cancelled = false;
    directoryKey(address, lookupIdentity).then(dirKey => {
      if (!cancelled) setResolved(kindFromDirectory(dirKey, messageKeyHex));
    });
    return () => { cancelled = true; };
  }, [address, messageKeyHex, local]);

  return local !== 'unknown' ? local : resolved;
}
