import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './useAuth';
import { useKeys } from './useKeys';
import { loginWithKeys, logoutToken, AccountRekeyedError } from '../api/client';
import { unlockKeystore, PasswordRequiredError } from '../crypto/reauth';
import { DevicePasswordRequiredError, attachedAddresses, loadDeviceKeystore, unlockDevice } from '../crypto/deviceKeystore';
import type { AuthMethod } from '../crypto/localKeystore';
import { importWorkingKeys, type WorkingKeys } from '../crypto/workingKeys';
import {
  canKeepUnlocked,
  describeHandle,
  lastAccount,
  listDeviceAccounts,
  loadUnlockedKeys,
  persistWorkingKeys,
  forgetAccount,
  type DeviceAccount,
} from '../accounts';
import { wokenAddresses } from '../push/woken';

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
  // Open every attached account at once. `prefer` names the account the app should then act as —
  // the one a tapped notification was for. Without it, see chooseTarget: mail waiting, then
  // whichever account this device was last using.
  unlockAll: (opts?: { password?: string; prefer?: string }) => Promise<boolean>;
}

/**
 * Which of the just-opened accounts the app then acts as.
 *
 * One unlock opens every attached mailbox, so this only decides where the person LANDS — the rest
 * are one click away in the switcher either way. In order: the account a tapped notification named;
 * one the worker has marked as having mail waiting; the account this device was last using.
 *
 * Only the first is certain. The second is what is knowable before any mailbox has been read — the
 * worker's mark, which is also what the picker calls "new mail" — and deliberately not a live
 * unread count for each account, which would mean a login and a mailbox read per account standing
 * between the unlock and the inbox. The third is the ordinary case, and it beats the alphabetical
 * first account, which is what this used to do.
 */
async function chooseTarget(unlocked: WorkingKeys[], prefer?: string): Promise<WorkingKeys> {
  const asked = unlocked.find(w => w.address === prefer);
  if (asked) return asked;
  const woken = await wokenAddresses(unlocked);
  const withMail = unlocked.find(w => woken.has(w.address));
  if (withMail) return withMail;
  const last = lastAccount();
  return unlocked.find(w => w.address === last) ?? unlocked[0];
}

function unlockErrorMessage(e: unknown): string {
  // The passkey path translates its own NotAllowedError (which conflates "cancelled"
  // with "nothing to offer") into something actionable; anything still raw here came
  // from elsewhere in the ceremony and is a plain dismissal.
  if (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
    return 'Unlock cancelled.';
  }
  // The key opened fine — it is simply no longer the account's. Trying again cannot help, and
  // the message has to say what does, or this reads as an unlock that keeps failing.
  if (e instanceof AccountRekeyedError) {
    return `${e.address} got a new key on another device, so this one can no longer sign in to it. `
      + 'Pair this device again to catch up. The mail already here stays readable.';
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
    void (async () => {
      const ks = await loadDeviceKeystore();
      if (!ks) { setDeviceUnlock(null); return; }
      // attachedAddresses, NOT Object.keys(ks.entries): an entry whose account has been re-wrapped
      // since (or has gone) opens nothing, and unlockDevice skips it. Counting the raw entries here
      // made this screen promise "open all N" and then deliver fewer — with the survivor being
      // whichever was attached most recently, since it is the one whose keystore has not moved.
      const addresses = await attachedAddresses();
      setDeviceUnlock(addresses.length ? { authMethod: ks.authMethod, addresses } : null);
    })();
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
      const token = await loginWithKeys(account.address, wk.ed25519Sign, wk.ed25519Public);

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
      const { opened, skipped } = await unlockDevice({ password: o?.password });
      const unlocked: WorkingKeys[] = [];
      // Accounts this unlock opened but the browser would not keep. They are only usable while this
      // page lives, so the one adopted below works and the rest read as locked the moment anything
      // asks — which is the whole failure, and it used to happen in silence.
      const notKept: Array<{ address: string; why: string }> = [];
      for (const [addr, kp] of Object.entries(opened)) {
        const wk = await importWorkingKeys(addr, kp);
        try {
          await persistWorkingKeys(wk);
          // Read it back rather than trusting the write. A resolved put is not the same as a
          // readable handle: these are non-extractable CryptoKeys going through structured clone,
          // and that is exactly where a browser quietly declines. describeHandle says WHICH part
          // came back wrong, because the four causes need four different fixes.
          // On a browser known not to keep handles, persistWorkingKeys does not even try, and
          // describing the absence would be reporting a decision as a fault.
          if (await canKeepUnlocked()) {
            const why = await describeHandle(addr);
            if (why) notKept.push({ address: addr, why });
          }
        } catch (e) {
          notKept.push({ address: addr, why: `storing it failed (${e instanceof Error ? e.name : 'unknown'})` });
        }
        unlocked.push(wk);
      }
      const target = await chooseTarget(unlocked, o?.prefer);
      // Mint the incoming session before adopting anything, for the same reason switchTo does.
      const token = await loginWithKeys(target.address, target.ed25519Sign, target.ed25519Public);
      adoptKeys(target);
      setSession(target.address, token);
      setNeedsDevicePassword(false);
      setNeedsPassword(null);
      // Two quite different outcomes, and they used to read as one. `skipped` really did not open —
      // the device secret could not reach them, and they are not available. `notKept` opened and
      // are usable right now; the browser just would not store them, so they lock again on reload
      // rather than being lost. Saying "did not open" for the second was simply wrong.
      const fleeting = notKept.filter(k => k.address !== target.address);
      const parts: string[] = [];
      if (skipped.length) {
        parts.push(`${skipped.length === 1 ? 'One account did' : `${skipped.length} accounts did`} `
          + `not open: ${skipped.map(sk => `${sk.address} — ${sk.reason}`).join('; ')}`);
      }
      if (fleeting.length) {
        parts.push(`this browser would not store ${fleeting.map(k => k.address).join(', ')}, so `
          + `${fleeting.length === 1 ? 'it is' : 'they are'} open now but will need unlocking again `
          + `after a reload (${fleeting.map(k => k.why).join('; ')})`);
      }
      // Nothing here about a browser that cannot keep handles across a reload. It used to say so,
      // and it stopped the one browser that behaves this way (WebKit, so every iOS device) on this
      // screen after a completely successful unlock — every mailbox open and ready — to report a
      // property of the browser. It is a standing fact rather than an outcome of this unlock, the
      // settings page states it beside the switch it actually qualifies, and the cost of repeating
      // it here was the inbox, every single time.
      if (parts.length) {
        // Deliberately no navigate: this screen is the only place either message will be read, and
        // going straight to the inbox leaves the person to discover the shortfall on their own.
        // Everything that opened is open; Continue is one click away.
        setError(`Unlocked ${target.address}, but ${parts.join('; and ')}.`);
        void refresh();
        return true;
      }
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
