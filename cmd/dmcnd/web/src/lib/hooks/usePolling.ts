import { useEffect, useRef } from 'react';

// usePolling runs tick every intervalMs while the tab is visible and online, and again the
// moment the tab becomes visible, regains connectivity or (by default) focus. Backgrounded
// tabs pause — better for battery, and they can do nothing useful offline. It is the ONE
// polling scaffold every synced store hook uses; tick is read through a ref, so the caller
// passes its latest closure without re-arming the timer.
export function usePolling(tick: () => void, intervalMs: number, opts: { onFocus?: boolean } = {}): void {
  const tickRef = useRef(tick);
  tickRef.current = tick;
  const onFocus = opts.onFocus ?? true;
  useEffect(() => {
    const run = () => {
      if (document.visibilityState === 'visible' && navigator.onLine) tickRef.current();
    };
    const id = window.setInterval(run, intervalMs);
    document.addEventListener('visibilitychange', run);
    window.addEventListener('online', run);
    if (onFocus) window.addEventListener('focus', run);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', run);
      window.removeEventListener('online', run);
      if (onFocus) window.removeEventListener('focus', run);
    };
  }, [intervalMs, onFocus]);
}
