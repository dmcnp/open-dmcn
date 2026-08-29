import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { deployment } from '@deployment';
import './styles/tokens.css';

// Title the tab after whatever this deployment calls itself (see lib/deployment.ts).
// Falls back to the title in index.html when it names nothing.
if (deployment.branding.documentTitle) document.title = deployment.branding.documentTitle;

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
