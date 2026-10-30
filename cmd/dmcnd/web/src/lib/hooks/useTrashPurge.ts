import { useEffect, useRef, useState } from 'react';
import { useFlags } from './useFlags';
import { useMessages } from './useMessages';
import { useSent, isSentStoreHash } from './useSent';
import { useSettings } from './useSettings';
import { expiredTrash, trashDays } from '../trash';

// How often an open client looks again for deleted mail whose time is up. Retention is counted in
// days, so an hour late is the worst it gets while a client is open.
const SWEEP_MS = 60 * 60 * 1000;

/**
 * Removes for good the mail that has waited in Deleted for as long as the account keeps it
 * (lib/trash.ts). Mounted once in the shell, so it runs whenever an unlocked client is open.
 *
 * Nothing is decided until the mailbox, Sent, the flags and the settings have all answered: a
 * message missing from a listing that has not landed yet is not a message that is gone, and the
 * retention is not the default just because the settings have not been read. A message the full
 * listing no longer holds (removed on another device, or by another tab of this one) only has its
 * flag record cleared. A delete that fails keeps the flag, so the next sweep tries again rather
 * than letting the message reappear where it came from.
 */
export function useTrashPurge(): void {
  const { flags, ready: flagsReady, removeFlags } = useFlags();
  const { messages, loaded: mailLoaded, accessState, deleteMessage } = useMessages();
  const { sent, loaded: sentLoaded, deleteSent } = useSent();
  const { settings, loaded: settingsLoaded } = useSettings();
  const [tick, setTick] = useState(0);
  const inFlight = useRef(new Set<string>());

  useEffect(() => {
    const t = setInterval(() => setTick(n => n + 1), SWEEP_MS);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!flagsReady || !mailLoaded || !sentLoaded || !settingsLoaded || accessState !== 'ok') return;
    const due = expiredTrash(flags, trashDays(settings.trashDays), Date.now()).filter(h => !inFlight.current.has(h));
    if (due.length === 0) return;
    const inMailbox = new Set(messages.map(m => m.hash));
    const inSent = new Set(sent.map(p => p.hash));
    for (const hash of due) {
      inFlight.current.add(hash);
      void (async () => {
        try {
          if (isSentStoreHash(hash)) {
            if (inSent.has(hash)) await deleteSent(hash);
          } else if (inMailbox.has(hash)) {
            await deleteMessage(hash);
          }
          await removeFlags(hash);
        } catch (err) {
          console.warn('Deleted: could not remove a message for good; trying again later', err);
        } finally {
          inFlight.current.delete(hash);
        }
      })();
    }
  }, [tick, flags, flagsReady, messages, mailLoaded, sent, sentLoaded, settings.trashDays, settingsLoaded, accessState, deleteMessage, deleteSent, removeFlags]);
}
