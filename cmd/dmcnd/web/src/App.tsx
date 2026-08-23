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
import { Register } from './pages/Register';
import { Petition } from './pages/Petition';
import { Import } from './pages/Import';
import { InboxMain } from './pages/InboxMain';
import { Contacts } from './pages/Contacts';
import { Settings } from './pages/Settings';
import { AppLayout } from './components/AppLayout';
import { SessionRenewer } from './components/SessionRenewer';
import { PETITION_MODE } from './lib/config';

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
            {/* One route, two pages, chosen by where the domain root key is. A live domain
                cannot mint an address, so /register is the petition flow there — the daemon does
                not even route POST /api/v1/register in that mode. */}
            <Route path="/register" element={PETITION_MODE ? <Petition /> : <Register />} />
            <Route path="/import" element={<Import />} />
            {/* Authenticated app: one persistent shell (sidebar + top bar + compose);
                the active section renders in the main column via <Outlet/>. */}
            <Route element={<ProtectedRoute><AppLayout /></ProtectedRoute>}>
              <Route path="/inbox" element={<InboxMain />} />
              <Route path="/contacts" element={<Contacts />} />
              <Route path="/settings" element={<Settings />} />
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
