import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { deployment } from '@deployment';
import { registerServiceWorker } from './lib/registerServiceWorker';
import './styles/tokens.css';

// Title the tab after whatever this deployment calls itself (see lib/deployment.ts).
// Falls back to the title in index.html when it names nothing.
if (deployment.branding.documentTitle) document.title = deployment.branding.documentTitle;

// The offline shell, and the worker a background notification is delivered to. Shipped for a long
// time and never registered until now.
registerServiceWorker();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
