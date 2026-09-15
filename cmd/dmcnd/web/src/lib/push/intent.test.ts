import { describe, expect, it } from 'vitest';
import { parseIntentUrl } from './intent';

// A tapped notification for an account this browser has not unlocked opens the app at a URL naming
// that account, because the worker cannot navigate an app window itself. That parameter is read and
// removed before the router runs — the redirect to /login would drop the query string, and a value
// left in the address bar would re-route the app on every reload.
//
// The parking itself is two lines of sessionStorage; what is worth pinning is which values are
// believed, and that removing ours leaves the rest of the URL alone.

const BASE = 'https://mail.example';

describe('parseIntentUrl', () => {
  it('takes the id out and leaves the path', () => {
    expect(parseIntentUrl(`${BASE}/inbox?woke=0123456789abcdef`))
      .toEqual({ id: '0123456789abcdef', url: '/inbox' });
  });

  it('keeps any other parameters and the fragment', () => {
    expect(parseIntentUrl(`${BASE}/inbox?thread=7&woke=0123456789abcdef#m2`))
      .toEqual({ id: '0123456789abcdef', url: '/inbox?thread=7#m2' });
  });

  it('reports nothing when the parameter is absent', () => {
    const href = `${BASE}/inbox?thread=7`;
    expect(parseIntentUrl(href)).toEqual({ id: null, url: href });
  });

  // The value names which mailbox to open. Anything not shaped like one of our ids is somebody
  // else's parameter — believing it would at best route nowhere, and it must not be eaten either.
  it.each([
    '../../etc/passwd',
    'not-hex',
    '0123456789ABCDEF',   // ids are lowercase hex
    '0123456789abcde',    // one short
    '0123456789abcdef0',  // one long
    '',
  ])('ignores %o', (value) => {
    const href = `${BASE}/inbox?woke=${encodeURIComponent(value)}`;
    expect(parseIntentUrl(href)).toEqual({ id: null, url: href });
  });

  it('survives something that is not a URL at all', () => {
    expect(parseIntentUrl('not a url')).toEqual({ id: null, url: 'not a url' });
  });
});
