import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { DEFAULT_DOMAIN } from './lib/config';
import './styles/tokens.css';

// Title the tab after the DEPLOYMENT, not after a product. This client ships with no
// branding of its own — whoever runs the daemon is the identity a user should see, so a
// self-hoster on example.org gets "example.org mail". Falls back to the neutral title in
// index.html when no domain is configured.
if (DEFAULT_DOMAIN) document.title = `${DEFAULT_DOMAIN} mail`;

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
);

// Register the PWA service worker (offline app shell). Only in secure contexts
// (HTTPS / localhost); ignored where unsupported. The SW never caches /api.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      /* SW registration is best-effort; the app works fully without it. */
    });
  });
}
