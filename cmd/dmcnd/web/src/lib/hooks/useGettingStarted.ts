// Whether this account has a Getting started page, whether it is still showing, and putting it
// away. One place, because three surfaces ask (the rail row, the landing, the Inbox's empty state)
// and they must agree: a row the landing ignores, or a landing on a page the rail no longer lists,
// is the kind of disagreement people notice.
import { useCallback } from 'react';
import { deployment } from '@deployment';
import { useSettings } from './useSettings';

export function useGettingStarted() {
  const { settings, loaded, updateSettings } = useSettings();
  // An account that ends on its own (a demo address) has nothing to get started with.
  const available = !!deployment.gettingStarted && !deployment.expiring;
  // Only once the account's settings are read: before that, "hidden" is unknown, and a row that
  // appears and then vanishes is worse than one that appears a moment late.
  const visible = available && loaded && !settings.gettingStartedHidden;
  // The page's own Hide button puts it away; the switch in Settings → Appearance brings it back.
  const setShown = useCallback((show: boolean) => updateSettings({ gettingStartedHidden: !show }), [updateSettings]);
  const hide = useCallback(() => setShown(false), [setShown]);
  return { available, visible, loaded, hide, setShown };
}
