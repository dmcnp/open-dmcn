import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './useAuth';
import { useKeys } from './useKeys';
import { loginWithKeys, logoutToken } from '../api/client';
import { unlockKeystore, PasswordRequiredError } from '../crypto/reauth';
import { DevicePasswordRequiredError, loadDeviceKeystore, unlockDevice } from '../crypto/deviceKeystore';
import type { AuthMethod } from '../crypto/localKeystore';
import { importWorkingKeys, type WorkingKeys } from '../crypto/workingKeys';
import {
  listDeviceAccounts,
  loadUnlockedKeys,
  persistWorkingKeys,
  forgetAccount,
  type DeviceAccount,
} from '../accounts';

// Signing in as one of this device's identities — shared by the login picker and the
// header's account switcher, which are the same act from different starting points.
//
// The ORDER inside switchTo is the substance here. Doing the network hop before any
// context update is what makes a switch atomic: the key context and the session must
// change in a single render, or the mailbox sync briefly runs with the incoming
// account's key against the outgoing account's session token and signs the wrong
// mailbox's challenge. Everything downstream (messages, flags, labels, contacts,
// settings) re-homes on its own — each provider tears down on
// [keys, sessionToken, isAuthenticated].

export interface AccountSwitch {
  accounts: DeviceAccount[] | null; // null while the first IndexedDB read is in flight
  refresh: () => Promise<void>;
  busy: boolean;
  error: string;
  // The account awaiting an inline unlock. Consumers show a password field for a
  // password-gated keystore; a passkey one is already prompting.
  needsPassword: string | null;
  beginUnlock: (account: DeviceAccount) => void;
  cancelUnlock: () => void;
  switchTo: (account: DeviceAccount, opts?: { password?: string }) => Promise<boolean>;
  forget: (account: DeviceAccount) => Promise<void>;
  // Whether this device has a shared unlock set up, and which accounts it opens. Readable without
  // unlocking anything — it comes from the clear half of the device record.
  deviceUnlock: { authMethod: AuthMethod; addresses: string[] } | null;
  // True once a shared unlock has been attempted and the device's secret is a password.
  needsDevicePassword: boolean;
  // Open every attached account at once. `prefer` picks which of them the app then acts as —
  // the account a tapped notification named, when there was one.
  unlockAll: (opts?: { password?: string; prefer?: string }) => Promise<boolean>;
}

function unlockErrorMessage(e: unknown): string {
  // The passkey path translates its own NotAllowedError (which conflates "cancelled"
  // with "nothing to offer") into something actionable; anything still raw here came
  // from elsewhere in the ceremony and is a plain dismissal.
  if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
    return 'Unlock cancelled.';
  }
  return e instanceof Error ? e.message : 'Unlock failed';
}

export function useAccountSwitch(opts?: { onSwitched?: (address: string) => void }): AccountSwitch {
  const [accounts, setAccounts] = useState<DeviceAccount[] | null>(null);
  const [needsPassword, setNeedsPassword] = useState<string | null>(null);
  const [needsDevicePassword, setNeedsDevicePassword] = useState(false);
  const [deviceUnlock, setDeviceUnlock] = useState<{ authMethod: AuthMethod; addresses: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { address, sessionToken, setSession } = useAuth();
  const { keys, adoptKeys } = useKeys();
  const navigate = useNavigate();

  const busyRef = useRef(false);
  const needsPasswordRef = useRef<string | null>(null);
  needsPasswordRef.current = needsPassword;
  const onSwitchedRef = useRef(opts?.onSwitched);
  onSwitchedRef.current = opts?.onSwitched;

  const refresh = useCallback(async () => {
    setAccounts(await listDeviceAccounts());
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    void loadDeviceKeystore().then(ks => {
      setDeviceUnlock(ks ? { authMethod: ks.authMethod, addresses: Object.keys(ks.entries).sort() } : null);
    });
  }, []);

  const switchTo = useCallback(async (account: DeviceAccount, o?: { password?: string }): Promise<boolean> => {
    if (busyRef.current) return false;
    // Already acting as this account (the picker's "Continue" on the live session).
    if (account.address === address && keys) { navigate('/inbox'); return true; }

    busyRef.current = true; setBusy(true); setError('');
    const prevAddress = address;
    const prevToken = sessionToken;
    try {
      // A locked account skips the handle probe entirely: an IndexedDB round trip
      // here would sit between the click and navigator.credentials.get() and can
      // cost the passkey prompt its transient user activation.
      let wk = account.unlocked ? await loadUnlockedKeys(account.address, account.ks) : null;
      if (!wk) {
        if (!account.ks) {
          // Unlocked-only account (temporary session) whose handle is gone: there is
          // no at-rest copy to unlock, so it can't come back.
          setError(`${account.address} is no longer available on this device.`);
          await refresh();
          return false;
        }
        try {
          const { kp } = await unlockKeystore(account.ks, { password: o?.password });
          wk = await importWorkingKeys(account.address, kp);
        } catch (e) {
          if (e instanceof PasswordRequiredError) {
            // Re-prompting the same account means an empty submission, not a first ask.
            if (needsPasswordRef.current === account.address) setError('Password required.');
            setNeedsPassword(account.address);
            return false;
          }
          throw e;
        }
      }

      // Mint the incoming session BEFORE anything is persisted or adopted: the login
      // endpoints skip session renewal, so the outgoing bearer still installed here is
      // inert, and a failure leaves the outgoing account untouched and still signed in.
      const token = await loginWithKeys(account.address, wk.ed25519Sign);

      try {
        await persistWorkingKeys(wk);
      } catch {
        // Private mode / quota: the switch still works for this page's lifetime.
      }

      // One render: no await between these two, so React batches them and nothing
      // ever observes the new key alongside the old session.
      adoptKeys(wk);
      setSession(account.address, token);

      setNeedsPassword(null);
      navigate('/inbox');
      onSwitchedRef.current?.(account.address);
      // End the outgoing session now that the incoming one is installed.
      if (prevToken && prevAddress && prevAddress !== account.address) {
        void logoutToken(prevToken).catch(() => { /* best effort; it expires anyway */ });
      }
      void refresh();
      return true;
    } catch (e) {
      setError(unlockErrorMessage(e));
      return false;
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [address, sessionToken, keys, adoptKeys, setSession, navigate, refresh]);

  /**
   * One unlock, every attached account.
   *
   * The same handover switchTo performs, done once for the account the app will act as — the
   * others are imported and persisted so the switcher finds them already unlocked, which is the
   * entire point: three accounts, one passkey prompt.
   */
  const unlockAll = useCallback(async (o?: { password?: string; prefer?: string }): Promise<boolean> => {
    if (busyRef.current) return false;
    busyRef.current = true; setBusy(true); setError('');
    const prevToken = sessionToken;
    const prevAddress = address;
    try {
      const pairs = await unlockDevice({ password: o?.password });
      const unlocked: WorkingKeys[] = [];
      for (const [addr, kp] of Object.entries(pairs)) {
        const wk = await importWorkingKeys(addr, kp);
        try {
          await persistWorkingKeys(wk);
        } catch {
          // Private mode / quota: this page's lifetime still has them.
        }
        unlocked.push(wk);
      }
      const target = unlocked.find(w => w.address === o?.prefer) ?? unlocked[0];
      // Mint the incoming session before adopting anything, for the same reason switchTo does.
      const token = await loginWithKeys(target.address, target.ed25519Sign);
      adoptKeys(target);
      setSession(target.address, token);
      setNeedsDevicePassword(false);
      setNeedsPassword(null);
      navigate('/inbox');
      onSwitchedRef.current?.(target.address);
      if (prevToken && prevAddress && prevAddress !== target.address) {
        void logoutToken(prevToken).catch(() => { /* best effort; it expires anyway */ });
      }
      void refresh();
      return true;
    } catch (e) {
      if (e instanceof DevicePasswordRequiredError) {
        // A blank submission on a device that already asked is an empty password, not a first ask.
        if (needsDevicePassword) setError('Password required.');
        setNeedsDevicePassword(true);
        return false;
      }
      setError(unlockErrorMessage(e));
      return false;
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [address, sessionToken, adoptKeys, setSession, navigate, refresh, needsDevicePassword]);

  const beginUnlock = useCallback((account: DeviceAccount) => {
    setError('');
    setNeedsPassword(account.address);
    // The click IS the WebAuthn gesture — prompt straight away rather than making the
    // user press a second button.
    if (account.ks?.authMethod === 'passkey') void switchTo(account);
  }, [switchTo]);

  const cancelUnlock = useCallback(() => {
    setNeedsPassword(null);
    setNeedsDevicePassword(false);
    setError('');
  }, []);

  const forget = useCallback(async (account: DeviceAccount) => {
    await forgetAccount(account.address);
    if (needsPasswordRef.current === account.address) setNeedsPassword(null);
    await refresh();
  }, [refresh]);

  return {
    accounts, refresh, busy, error, needsPassword, beginUnlock, cancelUnlock, switchTo, forget,
    deviceUnlock, needsDevicePassword, unlockAll,
  };
}
