import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { setReauthHandler, loginWithKeys } from '../lib/api/client';
import { deployment } from '@deployment';

// SessionRenewer wires up transparent session renewal. When an authenticated
// request comes back 401 (the 24h JWT expired), the API layer calls this handler
// to re-mint the token from the in-memory key — no passphrase, invisible to the
// user. If renewal can't recover (no unlocked key, or the re-login is rejected),
// it clears the session and redirects to login with an "expired" notice.
// Renders nothing; just registers/cleans up the handler.
export function SessionRenewer() {
  const { address, setSession, clearSession } = useAuth();
  const { keys } = useKeys();
  const navigate = useNavigate();

  useEffect(() => {
    // A renewal already in flight when the tab switches accounts would otherwise
    // resolve into setSession() for the account we just left, clobbering the new one.
    let stale = false;
    setReauthHandler(async () => {
      if (!address || !keys) return null;
      try {
        const token = await loginWithKeys(address, keys.ed25519Sign);
        if (stale) return null;
        setSession(address, token);
        return token;
      } catch {
        clearSession();
        navigate('/login', { state: { reason: 'expired' } });
        return null;
      }
    });
    // A second service, where this deployment has one, keeps its own session off the same
    // working key (see lib/deployment.ts). It is told which account is current; minting is
    // its business, not this component's.
    deployment.installAccountSession?.(address && keys ? { address, signKey: keys.ed25519Sign } : null);
    return () => {
      stale = true;
      setReauthHandler(null);
      deployment.installAccountSession?.(null);
    };
  }, [address, keys, setSession, clearSession, navigate]);

  return null;
}
