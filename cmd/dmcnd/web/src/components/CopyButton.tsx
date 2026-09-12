import { useEffect, useRef, useState } from 'react';
import { IconButton } from '../ds';
import { Icon } from './Icon';

// Puts one short string on the clipboard and says whether it got there.
//
// The clipboard reports nothing of its own, so a button that only acts is a button people press
// twice wondering whether it worked; the glyph becomes a tick for a moment instead. A write can
// also be refused outright — an insecure context, or a browser that gates the permission — and
// that has to be visible too, because the user's next move is to select the text by hand and
// they need to know that is now their job.
//
// Shared rather than product-only: an address is the thing this client asks people to pass
// around, and it is worth copying wherever one is shown.
export function CopyButton({ value, what, size = 14 }: { value: string; what?: string; size?: number }) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  // A copy near the end of the component's life would otherwise set state after unmount.
  useEffect(() => () => clearTimeout(timer.current), []);

  const subject = what ?? value;
  const label = state === 'done' ? `Copied ${subject}`
    : state === 'failed' ? `Couldn’t copy ${subject} — select it by hand`
      : `Copy ${subject}`;

  async function run() {
    clearTimeout(timer.current);
    try {
      await navigator.clipboard.writeText(value);
      setState('done');
    } catch {
      setState('failed');
    }
    timer.current = setTimeout(() => setState('idle'), 1800);
  }

  return (
    <IconButton size="sm" aria-label={label} title={label} onClick={() => void run()}>
      <Icon name={state === 'done' ? 'check' : state === 'failed' ? 'x' : 'copy'} size={size} />
    </IconButton>
  );
}
