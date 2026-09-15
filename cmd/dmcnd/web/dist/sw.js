/* DMCN Mail — service worker (Vite SPA build).
   App-shell precache + network-first runtime caching so the client opens
   offline. Encrypted message data and the live API are NEVER cached here; only
   the static shell (index.html, hashed JS/CSS, icons, manifest) is.
   Bump CACHE on any shell-caching logic change. */

const CACHE = 'dmcn-mail-v3';
/* The shell itself is deliberately NOT precached. It is served no-store because it carries a
   per-request CSP nonce and points at content-hashed assets, so a copy taken at install time is a
   copy nobody asked for. The network-first handler below caches it on the first real navigation,
   and that copy is the one that backs offline — same offline behaviour, a much shorter window in
   which a stale shell can reference assets a deploy has since replaced. */
const SHELL = ['/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE)
      // addAll fails the whole install if one 404s; add individually & tolerate misses.
      .then((cache) => Promise.allSettled(SHELL.map((url) => cache.add(url))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Don't touch cross-origin requests.
  if (url.origin !== self.location.origin) return;
  // Never cache the live API — always hit the network (mailbox sync, sends, etc.).
  if (url.pathname.startsWith('/api/')) return;

  /* Content-hashed build output is immutable: a new deploy publishes new URLs, so a hit can be
     served straight from the cache with no network round trip at all. This is the common case by
     far — every module, style and font of a page load — and going to the network for each of them
     first made the worker a tax on every request rather than a speed-up. */
  if (url.pathname.startsWith('/assets/')) {
    event.respondWith(
      caches.match(req).then((hit) => hit || fetch(req).then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }))
    );
    return;
  }

  /* Everything else — the shell itself, icons, the manifest — is network-first: the shell carries a
     per-request CSP nonce and points at the CURRENT asset hashes, so a stale one is worth avoiding
     whenever the network can be reached. The cache is the offline fallback, and a navigation with
     nothing cached for it falls back to the shell so the router can take over. */
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() =>
        caches.match(req)
          .then((cached) => cached || (req.mode === 'navigate' ? caches.match('/index.html') : undefined))
          // respondWith() throws "Failed to convert value to 'Response'" if handed undefined,
          // so a cache miss while the network is down must still resolve to a Response.
          .then((res) => res || new Response('Offline', { status: 504, headers: { 'Content-Type': 'text/plain' } }))
      )
  );
});
