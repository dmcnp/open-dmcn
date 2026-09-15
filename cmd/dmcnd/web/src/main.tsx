import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { deployment } from '@deployment';
import { registerServiceWorker } from './lib/registerServiceWorker';
import { captureIntentFromUrl } from './lib/push/intent';
import { initDevicePosture, migrateLegacyPosture } from './lib/devicePosture';
import './styles/tokens.css';

// Title the tab after whatever this deployment calls itself (see lib/deployment.ts).
// Falls back to the title in index.html when it names nothing.
if (deployment.branding.documentTitle) document.title = deployment.branding.documentTitle;

// The offline shell, and the worker a background notification is delivered to. Shipped for a long
// time and never registered until now.
registerServiceWorker();

// Before the router exists: an unauthenticated visitor is redirected to /login, and the redirect
// drops the query string that says which account a tapped notification was for.
captureIntentFromUrl();

// The lock posture decides which key every working handle is stored under, and it is read
// SYNCHRONOUSLY from there on (workingKeyRef is on every path that touches a handle). So it is
// loaded before the first render rather than raced against it: a component that wrote a handle
// under the default while the real posture was still loading would strand it under the wrong ref,
// which reads as a locked account.
void (async () => {
  await migrateLegacyPosture();
  await initDevicePosture();
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
})();
