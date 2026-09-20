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
import type { WorkingKeys } from './crypto/workingKeys';
import type { RotatedSibling } from './crypto/rotation';

// InboxNotice is one kind of request-shaped control message, surfaced as a row at the top of
// the inbox. The shell owns the row and the dialog it opens; the deployment owns which kinds
// exist and what opening one shows.
//
// The row's words are the SHELL's, never the requester's. A request of this shape is
// unauthenticated inbound mail — anyone who knows an address can put one in its mailbox — and
// text pinned above someone's mail, in the app's own chrome, reads as the app speaking. So a
// notice contributes a subject to count and a sentence about how many; whatever the requester
// called itself belongs inside the dialog, framed as a claim.
export interface InboxNotice {
  // The control subject whose presence in the mailbox raises this notice. Must also appear in
  // controlSubjects, or the requests show up as mail as well.
  subject: string;
  // Row and dialog icon (Icon name).
  icon: string;
  // Dialog title.
  title: string;
  // The row's sentence, given how many are pending.
  summary: (count: number) => string;
  // What opening the row shows. Rendered inside the dialog body, and kept mounted while the
  // dialog is open even after the last request is gone, so a result stays readable.
  view: ComponentType<{ onClose: () => void }>;
}

// AccountIdentity is one address of an account together with the keys that act as it. For a
// shared alias `keys` is the account's own working set; for an isolated alias it is a derived
// set that the deployment holds only as non-extractable handles.
export interface AccountIdentity {
  address: string;
  keys: WorkingKeys;
  kind: 'shared' | 'isolated';
  // Set once the address has retired itself. Its key stays in the ring — that is what keeps mail
  // it already delivered readable — but it is no longer an address anything may write from, so
  // the composer's From row leaves it out.
  retiredAt?: number;
}

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
  // Extra addresses on the same account, if this deployment can mint them. Rendered as its own
  // card in Settings; absent ⇒ no card, which is the honest answer on a deployment whose
  // addresses are assigned out of band (the reference daemon answers petitions from an offline
  // root and has no alias concept). Receives the working keys because the alias record is
  // self-signed by the account's own key — that signature is what makes the alias the owner's.
  aliases?: ComponentType<{ address: string; keys: WorkingKeys }>;
  // Using an address at a domain the account holder owns. Product-only, and for the same reason
  // aliases are: the reference daemon serves one domain that its operator already controls, so
  // there is nothing to bring. Absent ⇒ no card, exactly as with aliases.
  //
  // Receives the working keys because the customer's mailbox key IS the domain root — the browser
  // signs the domain record with it, and that signature is the whole of the customer's consent.
  customDomain?: ComponentType<{ address: string; keys: WorkingKeys }>;
  // Ask this deployment's account service to attest a device — the domain's signed record that it
  // saw this device key on this address at this moment.
  //
  // Deployment-specific because attesting anything needs an ONLINE key holding the domain's
  // 'device' grant, and a single-binary self-host deliberately has no such service: its root is
  // offline and its credentials are signed by hand. Absent ⇒ devices enrol with no credential,
  // which is the honest answer there and costs only the ability to authorize a key rotation —
  // that rule is checked by nodes holding no registry, and the credential is all they would have
  // to go on.
  //
  // Returns the moment it recorded, which the caller uses as the device's enrolment time so the
  // credential and the registry cannot disagree about it. Null when the domain issues none.
  deviceCredential?: (address: string, devicePub: Uint8Array) => Promise<{ credential: Uint8Array; issuedAt: number } | null>;
  // Publish a rotated identity record, with the complete history that explains it.
  //
  // Deployment-specific because a rotation needs the domain's operator-owned credentials REISSUED
  // against the new key — the address attestation and the routing credential that carries the
  // mailbox's relay hints. Without that the account publishes fine and lands unverified with
  // nowhere to receive. Only a deployment with an online issuer can do it; a self-host whose root
  // is offline re-issues by hand, so this is absent there and the ceremony refuses to start.
  publishRotation?: (record: Uint8Array, history: Uint8Array, siblings: RotatedSibling[]) => Promise<void>;
  /**
   * The Settings panel that re-keys this account, where the deployment offers one.
   *
   * It frames itself, like the other self-framing sections: whether re-keying is offered at all
   * depends on the domain's policy and on the fleet, and a heading drawn over an empty box would
   * promise something the answer may be no to.
   */
  rotateKey?: ComponentType<{ address: string; keys: WorkingKeys }>;
  // Where a device's push endpoint is registered, for contentless new-mail notifications.
  //
  // Only this step is deployment-specific: the permission prompt, the subscribe call, the settings
  // card and the open-time reconcile are all shared. The product hands the endpoint to a mailbox
  // relay over a signed mailbox op (its web backend and its relays are separate processes); a
  // single-binary self-host writes it locally, with no protocol involved at all.
  //
  // Absent ⇒ no notifications card, exactly as with aliases. Registration carries the working keys
  // because the relay authorises it the way it authorises every mailbox op: by the owner's
  // signature over a nonce.
  push?: {
    // The notification worker's URL. Registered once per account under a scope of its own, so
    // each account holds its own push subscription — shared code must not assume a product asset
    // path, and a deployment that serves its worker from elsewhere says so here.
    workerUrl: string;
    register(address: string, endpoint: string, keys: WorkingKeys): Promise<void>;
    unregister(address: string, endpoint: string, keys: WorkingKeys): Promise<void>;
  };
  // The account's other addresses, with the keys that read and send as each: a shared alias
  // is the account's own keypair under another name; an isolated one carries keys the
  // deployment derives from the account (see WorkingKeys.aliasRoot). The composer offers a From
  // row when this returns any, the mailbox uses it to open mail sealed to a derived key, and
  // the reader labels such mail with the address it arrived at. Called often — once per
  // mailbox poll — so the deployment should cache and refresh on its own terms. explicitToken
  // names a background account's session (the unread counter); absent ⇒ the signed-in one.
  // Absent from the seam ⇒ one address, one key.
  identities?: (keys: WorkingKeys, explicitToken?: string) => Promise<AccountIdentity[]>;

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
  // Subjects that mark a control message, kept out of every folder.
  controlSubjects: string[];
  // Which of those subjects announce themselves at the top of the inbox, and what each one
  // opens. Absent ⇒ control messages have no surface of their own.
  inboxNotices?: InboxNotice[];
}
