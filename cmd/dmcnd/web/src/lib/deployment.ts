// The deployment seam.
//
// One client, two front doors: the hosted product and the open reference daemon share
// this whole tree except for a handful of decisions that are genuinely properties of the
// DEPLOYMENT, not of the mail client. Those decisions are declared here as an interface
// and supplied by src/deployment.ts, which is the one module each build owns.
//
// A difference belongs here only if both answers are correct — the product verifying a
// bridge against its fleet operator key server-side and the reference verifying it in the
// browser against the domain root are both right for their own trust anchor. A difference
// that is merely older on one side is drift, and belongs in neither: fix it in both.

import type { ComponentType, ReactNode } from 'react';
import type { BridgeAttestation } from './crypto/bridgeAttest';
import type { DeliveryReceiptView } from './crypto/receiptAttest';
import type { MailFilterFactory } from './api/filterList';
import type { StorageUsage } from './api/personalStore';

export interface Deployment {
  // Who this client says it is, on the pre-auth screens.
  //
  // The product is a brand and says so. The reference client deliberately is not: it ships
  // with no product identity, because it is the webmail a daemon serves and the only name
  // worth showing is the DEPLOYMENT's own domain — whoever runs it. A reference
  // implementation should not sell anything, and a self-hoster should not have to strip
  // someone else's brand out of their own mail client.
  branding: {
    // Shown above the form on sign-in, register, import and pairing.
    mark: ReactNode;
    // The reassurance line under the form. Note who is entitled to say what: a hosted
    // provider can promise "we can't read your mail"; a client with no provider behind it
    // can only state the property that is true of the software itself.
    note: ReactNode;
    // An optional panel beside the form. Absent ⇒ the form is the whole screen.
    authPanel?: ReactNode;
    // Shown in the signed-in app's header. The reference names the SERVER you are signed
    // in to, which is the useful fact when the client itself is unbranded; a product names
    // itself. Absent ⇒ nothing sits there.
    appMark?: ReactNode;
    // The browser tab title. The reference names the DEPLOYMENT (a self-hoster on
    // example.org gets "example.org mail"); a product names itself.
    documentTitle?: string;
  };

  // What /register renders. A hosted front door shows a signup form; a self-hosted domain
  // whose root key is offline cannot mint an address at all and shows a petition instead.
  registerScreen: ReactNode;
  // Some deployments front the mail client with a SECOND service (registration, billing,
  // countersigning) that keeps its own challenge-response session — deliberately sharing no
  // secret with the mail client, each verifying identities independently.
  //
  // Called whenever the signed-in account changes, with the account to mint for or null to
  // tear down. A deployment with no such service leaves this out and nothing is minted.
  installAccountSession?: (account: { address: string; signKey: CryptoKey } | null) => void;

  // What the sign-in page offers someone without an account here. Both the wording and the
  // destination belong to the deployment: a domain that cannot mint an address on demand must
  // not invite anyone to "create" one, and a front door with no public signup should either
  // send them elsewhere or say nothing at all.
  signUp: {
    // The whole footer sentence under the sign-in form. null offers nothing.
    prompt: ReactNode;
    // The short inline variant, offered beside an existing account list.
    inline: ReactNode;
  };
  // Whether an existing identity can be brought onto this device by pairing with a device
  // that already holds it — and if so, where that flow lives. Absent ⇒ this deployment has
  // no pairing, and the sign-in screen offers none.
  //
  // Absent is the default because pairing is not a setting a deployment can simply switch
  // on: it needs the flow itself (a pre-auth screen here, a responder on the other device,
  // and control messages the mail UI must recognise but never show), all of which a
  // deployment supplies or does not. A build without it must not advertise it — on the
  // empty-device screen the pairing button is the PRIMARY action, and a primary action
  // that routes nowhere lands the reader back on sign-in with no explanation.
  //
  // The path is carried here rather than assumed so this and authRoutes cannot disagree:
  // whatever registers the screen is what the sign-in page links to.
  pairing?: { path: string };
  // Extra pre-auth screens (outside the signed-in shell), e.g. device pairing.
  authRoutes: { path: string; element: ReactNode }[];
  // Extra sections inside the signed-in shell, e.g. an admin console.
  appRoutes: { path: string; element: ReactNode }[];
  // Whether more personal storage can be bought here, and how. Rendered inside the shared
  // Storage card in Settings; absent ⇒ the card just reports usage, which is the honest
  // answer on a deployment that sells nothing.
  storageUpgrade?: ComponentType<{ usage: StorageUsage | null; onChanged: () => void }>;

  // The left-rail rows for those sections. A component rather than a data list because the
  // rows carry live counts (pending device pairings, address requests) that only the
  // deployment knows how to derive — it reads them from the same hooks the shell does.
  appNav?: ComponentType<{ collapsed: boolean; pathname: string; goto: (path: string) => void }>;

  // How a bridge's signed SPF/DKIM/DMARC classification is verified. Both implementations
  // answer the same question — "is this attestation from a bridge I trust, about THIS
  // message?" — against different trust anchors:
  //
  //   product   POSTs the attachment to its own backend, which checks the bridge's fleet
  //             credential against the operator key it holds.
  //   reference verifies the credential chain in the browser against the domain root key
  //             published in the domain's _dmcn DNS fingerprint.
  //
  // senderPub is the carrying message's already-verified sender key; every implementation
  // MUST bind the attestation to it, or a genuine verdict can be lifted off one message
  // and stapled onto another. Implementations never throw: the wrapper fails closed, but
  // returning a verdict with a reason gives the reader something true to display.
  verifyClassification: (classification: Uint8Array, senderPub: Uint8Array | null) => Promise<BridgeAttestation>;

  // The same, for a bridge's delivery receipt on outbound-to-legacy mail.
  verifyReceipt: (receipt: Uint8Array, senderPub: Uint8Array | null) => Promise<DeliveryReceiptView>;

  // How to reach a recipient the directory has no identity for, if this deployment can at
  // all. Two shapes, both correct: a directory that answers such a lookup by pointing at its
  // own outbound bridge needs nothing here — the normal send path already has an address to
  // seal to — while one that answers 404 supplies the fallback that finds a bridge and stores
  // to it. Absent ⇒ a legacy recipient is unreachable, and the send says so.
  //
  // The split of duties is deliberate: `seal` and `sign` come from the composer, which owns
  // the keys and the content, so a deployment decides only WHERE a message goes and never
  // what is in it or what signs it.
  sendToLegacy?: (ctx: {
    recipient: string;
    senderAddress: string;
    seal: (x25519Pub: Uint8Array) => Promise<Uint8Array>;
    sign: (bytes: Uint8Array) => Promise<Uint8Array>;
  }) => Promise<string>;

  // How the account's block/allow list is stored — and therefore whether a block is
  // enforced at the relay or only honoured by this client. See lib/api/filterList.ts.
  mailFilter: MailFilterFactory;

  // Message payloads the deployment carries for its OWN protocol purposes, which the mail
  // UI must recognise but never show as mail. The product moves device-pairing and
  // countersign traffic over ordinary messages; the reference protocol carries neither, so
  // both lists are empty there. Declared rather than hard-coded because a client that
  // hard-codes a surface it does not have will hide mail it should have shown the moment
  // someone reuses that subject.

  // Attachment content types consumed elsewhere and hidden from a message's attachment list.
  internalAttachmentTypes: string[];
  // Subjects that mark a control message, surfaced in its own panel rather than a folder.
  controlSubjects: string[];
}
