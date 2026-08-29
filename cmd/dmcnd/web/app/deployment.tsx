// What THIS build is: the reference daemon's webmail.
//
// One process serves one domain, and it is the operator of that domain, so the trust anchor
// for a bridge is the domain's own root key — published in DNS as the _dmcn fingerprint and
// handed to the browser as DOMAIN_ROOT_PUB. Verification therefore runs here, in the browser:
// nothing about whether a bridged message looks trustworthy passes through the server.
//
// See lib/deployment.ts for what belongs in this file and what does not.

import type { Deployment } from '../src/lib/deployment';
import { MailFilterClient } from './lib/api/filterRest';
import { Icon } from '../src/components/Icon';
import { DEFAULT_DOMAIN, envVal } from '../src/lib/config';
import { Link } from 'react-router-dom';
import { Register } from './pages/Register';
import { Import } from './pages/Import';
import { Petition } from './pages/Petition';
import { verifyClassificationLocal, verifyReceiptLocal } from './lib/crypto/localBridgeVerify';

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;

// On a live domain whose root key is offline, nothing is created on demand — you ask an
// admin — so the wording changes with it, or the link promises something the page cannot do.
const PETITION_MODE = envVal('PETITION_MODE', '') === 'true';

export const deployment: Deployment = {
  branding: {
    // The deployment's own domain, or nothing — never a product name. A self-hoster on
    // example.org gets "example.org", which is the only identity a reader here should trust.
    mark: DEFAULT_DOMAIN ? (
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)' }}>
        <Icon name="mail" size={20} />
        <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-strong)' }}>{DEFAULT_DOMAIN}</span>
      </div>
    ) : null,
    // No "we": there is no provider behind this client, and on a self-hosted daemon the
    // operator may well be the reader themselves. State the property that is actually true
    // of the software — keys stay on the device — and claim nothing about who runs the server.
    note: 'Your keys are generated and kept on this device. Mail is decrypted here, never on the server.',
    // Named after the deployment, not after a product — see the note on branding above.
    documentTitle: DEFAULT_DOMAIN ? `${DEFAULT_DOMAIN} mail` : undefined,
    // In the app header, name the SERVER you are signed in to. With no product identity to
    // show, that is the useful fact — and on a self-hosted daemon it is the only one.
    appMark: DEFAULT_DOMAIN ? (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-strong)', marginRight: 'var(--space-2)', whiteSpace: 'nowrap' }}>
        <Icon name="mail" size={17} style={{ color: 'var(--text-muted)' }} />
        {DEFAULT_DOMAIN}
      </span>
    ) : null,
    // No marketing panel. A reference implementation should not sell anything.
  },
  // One route, two screens, chosen by where the domain root key is. A live domain whose root
  // is offline cannot mint an address, so /register asks an admin for a mailbox instead — and
  // the daemon does not even route POST /api/v1/register in that mode.
  registerScreen: PETITION_MODE ? <Petition /> : <Register />,
  signUp: {
    prompt: (
      <>Don't have a mailbox here yet?{' '}
        <Link to="/register" style={linkStyle}>{PETITION_MODE ? 'Ask for a mailbox' : 'Create an account'}</Link>
      </>
    ),
    inline: <Link to="/register" style={linkStyle}>{PETITION_MODE ? 'ask for a mailbox' : 'create'}</Link>,
  },
  // No device pairing and no admin console here: both are product surfaces.
  authRoutes: [{ path: '/import', element: <Import /> }],
  appRoutes: [],
  // The open protocol carries no control messages — device pairing and countersign
  // requests are product surfaces — so nothing is hidden from the mail folders here.
  mailFilter: (keys, explicitToken) => new MailFilterClient(keys, explicitToken),
  internalAttachmentTypes: [],
  controlSubjects: [],
  verifyClassification: verifyClassificationLocal,
  verifyReceipt: verifyReceiptLocal,
};
