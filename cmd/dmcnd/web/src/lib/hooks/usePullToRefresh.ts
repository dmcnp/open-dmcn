import { useEffect, useRef, useState } from 'react';
import type { RefObject } from 'react';

// Pull-to-refresh for a scrolling pane on a touch screen.
//
// The app shell is `100dvh; overflow: hidden` and scrolls a pane inside itself, so the
// browser's own pull-to-refresh — a document-scroll gesture — can never fire here: someone
// who pulls down on the inbox gets nothing, and a gesture that does nothing reads as an app
// that isn't listening. This implements it on the pane.
//
// The gesture is the platform one: drag down from the top of the list, and the list follows
// the finger; release past the threshold and it refreshes. The decision is made AT RELEASE
// against where the finger is THEN, not against how far it ever got — pulling down and back
// up again before lifting is a cancelled gesture and refreshes nothing.

/** Pull (px) at which the gesture arms: release at or past this and the list refreshes. */
export const PULL_THRESHOLD = 64;
/** Where the list rests while the refresh it started is still running. */
const PULL_REST = 48;
/** The furthest the list can be dragged, however far the finger travels. */
const PULL_MAX = 96;
/** Movement (px) before the gesture is classified at all — the same slop the rows' own
 *  swipe uses, so neither reads a tap or a jitter as a drag. */
const SLOP = 8;
/** Floor on how long the spinner stays up. A sync served from a warm connection can come
 *  back in a few frames, and an indicator that appears and vanishes inside one reads as a
 *  glitch rather than as an answer. */
const MIN_SPIN_MS = 450;

/** How far the list sits below its resting place for a finger that has travelled `dy`. */
export function pullDistance(dy: number): number {
  const d = dy - SLOP;
  if (d <= 0) return 0;
  // One-to-one out to the threshold, stiffening after it: the part of the gesture that
  // decides the outcome tracks the finger exactly, and past the point where pulling
  // further changes nothing, the list says so by resisting.
  if (d <= PULL_THRESHOLD) return d;
  return Math.min(PULL_MAX, PULL_THRESHOLD + (d - PULL_THRESHOLD) * 0.4);
}

export interface PullState {
  /** Pixels the list is currently held down by. */
  distance: number;
  /** True while releasing would refresh — reflects where the finger is now, so dragging
   *  back up disarms it again. */
  armed: boolean;
  /** True while the refresh this gesture started is still running. */
  refreshing: boolean;
  /** True while a finger is driving the pull; the list drops its transition then, so it
   *  tracks the finger instead of chasing it. */
  dragging: boolean;
}

/**
 * Wire pull-to-refresh to the scrolling element `ref` points at. `onRefresh` may return a
 * promise, and the indicator stays up until it settles. `enabled` is the caller's switch —
 * this is a touch gesture, and a pane that isn't the list (an open message) isn't it.
 */
export function usePullToRefresh(
  ref: RefObject<HTMLElement | null>,
  onRefresh: () => Promise<unknown> | void,
  enabled: boolean,
): PullState {
  const [distance, setDistance] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [dragging, setDragging] = useState(false);
  // Read through a ref so a new closure each render doesn't re-arm the listeners.
  const refreshRef = useRef(onRefresh);
  refreshRef.current = onRefresh;

  useEffect(() => {
    const el = ref.current;
    if (!el || !enabled) return;

    let live = true;       // false once this effect is torn down: a refresh may outlive it
    let busy = false;      // a refresh is running; further pulls are ignored until it ends
    let tracking = false;  // a touch started somewhere this gesture could begin
    let engaged = false;   // ...and turned out to be a downward pull, so it is ours
    let startX = 0, startY = 0, dist = 0;

    const onStart = (e: TouchEvent) => {
      // Only from the very top, and only a single finger: a pinch or a second touch
      // mid-scroll is not a pull.
      if (busy || e.touches.length !== 1 || el.scrollTop > 0) return;
      const t = e.touches[0];
      startX = t.clientX; startY = t.clientY;
      tracking = true; engaged = false; dist = 0;
    };

    const onMove = (e: TouchEvent) => {
      if (!tracking) return;
      if (e.touches.length !== 1) { tracking = false; return; }
      const t = e.touches[0];
      const dy = t.clientY - startY;
      const dx = t.clientX - startX;
      if (!engaged) {
        if (Math.abs(dy) < SLOP && Math.abs(dx) < SLOP) return; // still inside the slop
        // Classified once, on the first real movement, and never revisited: a pull is
        // downward, mostly vertical, and starts at the top. Anything else — scrolling back
        // into the list, a row's sideways swipe — belongs to whoever else is listening.
        if (dy <= 0 || Math.abs(dx) > Math.abs(dy) || el.scrollTop > 0) { tracking = false; return; }
        engaged = true;
        setDragging(true);
      }
      // Ours now: keep the browser from scrolling or rubber-banding underneath it.
      if (e.cancelable) e.preventDefault();
      dist = pullDistance(dy);
      setDistance(dist);
    };

    const finish = () => {
      if (!tracking) return;
      tracking = false;
      if (!engaged) return;
      engaged = false;
      setDragging(false);
      // Released short of the threshold (or dragged back up to it): the list springs back
      // and nothing is fetched.
      if (dist < PULL_THRESHOLD) { setDistance(0); return; }
      busy = true;
      setDistance(PULL_REST);
      setRefreshing(true);
      const started = Date.now();
      void Promise.resolve(refreshRef.current())
        // A failed sync is reported by the list itself, in its own error row. The spinner's
        // only job is to stop.
        .catch(() => {})
        .then(() => new Promise(r => window.setTimeout(r, Math.max(0, MIN_SPIN_MS - (Date.now() - started)))))
        .then(() => {
          busy = false;
          if (!live) return;
          setRefreshing(false);
          setDistance(0);
        });
    };

    const onCancel = () => {
      tracking = false;
      if (!engaged) return;
      engaged = false;
      setDragging(false);
      setDistance(0);
    };

    // touchmove must be non-passive to be able to preventDefault, which React's own
    // onTouchMove cannot promise — hence the manual registration.
    el.addEventListener('touchstart', onStart, { passive: true });
    el.addEventListener('touchmove', onMove, { passive: false });
    el.addEventListener('touchend', finish, { passive: true });
    el.addEventListener('touchcancel', onCancel, { passive: true });
    return () => {
      live = false;
      el.removeEventListener('touchstart', onStart);
      el.removeEventListener('touchmove', onMove);
      el.removeEventListener('touchend', finish);
      el.removeEventListener('touchcancel', onCancel);
      // The pull's visible state belongs to this pane, and the pane is going away — opening a
      // message mid-refresh gets here. A refresh still in flight resolves into `live` and
      // leaves it alone, so without this reset the list would come back held down under a
      // spinner that nothing would ever stop.
      setDistance(0);
      setRefreshing(false);
      setDragging(false);
    };
  }, [ref, enabled]);

  return { distance, armed: distance >= PULL_THRESHOLD, refreshing, dragging };
}
