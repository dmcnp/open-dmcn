/* DMCN Mail — service worker (Vite SPA build).
   App-shell precache + network-first runtime caching so the client opens
   offline. Encrypted message data and the live API are NEVER cached here; only
   the static shell (index.html, hashed JS/CSS, icons, manifest) is.
   Bump CACHE on any shell-caching logic change. */

const CACHE = 'dmcn-mail-v2';
const SHELL = ['/', '/index.html', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];

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

  // Network-first for the static shell: serve fresh when online (assets are
  // content-hashed, so freshness matters and stale hashes stay valid), falling
  // back to cache only when offline. Navigations fall back to the cached shell.
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
