import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './lib/hooks/useAuth';
import { KeysProvider, useKeys } from './lib/hooks/useKeys';
import { MessagesProvider } from './lib/hooks/useMessages';
import { SentProvider } from './lib/hooks/useSent';
import { FlagsProvider } from './lib/hooks/useFlags';
import { LabelsProvider } from './lib/hooks/useLabels';
import { SettingsProvider } from './lib/hooks/useSettings';
import { ContactsProvider } from './lib/hooks/useContacts';
import { MailFilterProvider } from './lib/hooks/useMailFilter';
import { Login } from './pages/Login';
import { InboxMain } from './pages/InboxMain';
import { Contacts } from './pages/Contacts';
import { Settings } from './pages/Settings';
import { AppLayout } from './components/AppLayout';
import { SessionRenewer } from './components/SessionRenewer';
import { deployment } from '@deployment';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  const { keys, loading } = useKeys();
  // Working handles load from IndexedDB asynchronously — wait rather than bounce the
  // user to login on a refresh before the restore resolves.
  if (loading) return null;
  // A valid session but no unlocked keys (e.g. a new tab, or the handles were
  // cleared) means we must re-unlock — send the user to login rather than show a
  // broken, keyless inbox.
  if (!isAuthenticated || !keys) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <AuthProvider>
      <KeysProvider>
        <MessagesProvider>
        <SentProvider>
        <FlagsProvider>
        <LabelsProvider>
        <SettingsProvider>
        <ContactsProvider>
        <MailFilterProvider>
        <BrowserRouter>
          <SessionRenewer />
          <Routes>
            <Route path="/login" element={<Login />} />
            {/* Registration and any extra pre-auth screens are the deployment's (see
                lib/deployment.ts): what it takes to get an address here is a property of
                who runs the domain, not of the mail client. */}
            <Route path="/register" element={deployment.registerScreen} />
            {deployment.authRoutes.map(r => <Route key={r.path} path={r.path} element={r.element} />)}
            {/* Authenticated app: one persistent shell (sidebar + top bar + compose);
                the active section renders in the main column via <Outlet/>. */}
            <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
              <Route path="/inbox" element={<InboxMain />} />
              <Route path="/contacts" element={<Contacts />} />
              <Route path="/settings" element={<Settings />} />
              {deployment.appRoutes.map(r => <Route key={r.path} path={r.path} element={r.element} />)}
            </Route>
            <Route path="*" element={<Navigate to="/inbox" replace />} />
          </Routes>
        </BrowserRouter>
        </MailFilterProvider>
        </ContactsProvider>
        </SettingsProvider>
        </LabelsProvider>
        </FlagsProvider>
        </SentProvider>
        </MessagesProvider>
      </KeysProvider>
    </AuthProvider>
  );
}
