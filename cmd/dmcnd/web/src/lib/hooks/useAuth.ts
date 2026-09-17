import { createContext, useContext, useState, useCallback, ReactNode, createElement } from 'react';
import { setSessionToken } from '../api/client';
import { rememberLastAccount } from '../accounts';

interface AuthState {
  isAuthenticated: boolean;
  address: string | null;
  sessionToken: string | null;
}

interface AuthContextValue extends AuthState {
  setSession: (address: string, token: string) => void;
  clearSession: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const saved = sessionStorage.getItem('dmcn_session');
    if (saved) {
      try {
        const { address, sessionToken } = JSON.parse(saved);
        setSessionToken(sessionToken);
        return { isAuthenticated: true, address, sessionToken };
      } catch {
        // ignore
      }
    }
    return { isAuthenticated: false, address: null, sessionToken: null };
  });

  const setSession = useCallback((address: string, token: string) => {
    setSessionToken(token);
    sessionStorage.setItem('dmcn_session', JSON.stringify({ address, sessionToken: token }));
    // Every road into acting as an account ends here, so this is the one place that can record
    // WHICH account without a caller having to remember to. The session itself is per-tab and
    // gone when the browser closes; this outlives it, and is the only thing left to say where a
    // device unlock should land next time.
    rememberLastAccount(address);
    setState({ isAuthenticated: true, address, sessionToken: token });
  }, []);

  const clearSession = useCallback(() => {
    setSessionToken(null);
    sessionStorage.removeItem('dmcn_session');
    sessionStorage.removeItem('dmcn_encrypted_payload');
    setState({ isAuthenticated: false, address: null, sessionToken: null });
  }, []);

  return createElement(AuthContext.Provider, { value: { ...state, setSession, clearSession } }, children);
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
