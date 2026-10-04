// The Getting started page: the deployment's content (deployment.gettingStarted) in the shell's
// page frame, with the one control the shell owns, putting it away.
//
// It is a destination rather than a banner because the moment it works is the moment a banner
// would disappear: the first message lands, the empty-inbox state it replaced is gone, and the
// second step ("put it where strangers find you") went with it. So it stays in the rail until the
// owner says they are done with it, and only then.
import { Navigate, useNavigate } from 'react-router-dom';
import { deployment } from '@deployment';
import { useAuth } from '../lib/hooks/useAuth';
import { useGettingStarted } from '../lib/hooks/useGettingStarted';
import { useIsMobile } from '../lib/useIsMobile';
import { PageShell } from '../components/PageShell';
import { Button } from '../ds';

export function GettingStarted() {
  const View = deployment.gettingStarted;
  const { address } = useAuth();
  const { visible, hide } = useGettingStarted();
  const navigate = useNavigate();
  const embedded = !useIsMobile();
  if (!View || !address) return <Navigate to="/inbox" replace />;

  const putAway = async () => {
    await hide();
    navigate('/inbox');
  };

  return (
    <PageShell
      embedded={embedded}
      title="Getting started"
      actions={visible ? <Button size="sm" variant="secondary" onClick={() => void putAway()}>Hide Getting started</Button> : undefined}
    >
      <View address={address} />
    </PageShell>
  );
}
