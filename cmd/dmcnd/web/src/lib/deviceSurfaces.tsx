// What a deployment with a device registry and pairing fills its seam with.
//
// A registry is something a server has or doesn't, so each of these stays a seam entry: a
// deployment without one leaves them out and the shell offers none of it. But every deployment
// that has one has the same one (SPEC_EXT_DEVICES.md), so the pieces live here, once, and each
// build's deployment.tsx only says "this server has devices".

import type { ReactNode } from 'react';
import type { Deployment, InboxNotice } from './deployment';
import { PairDevice } from '../pages/PairDevice';
import { DeviceRequests } from '../components/DeviceRequests';
import { DeviceManager } from '../components/DeviceManager';
import { RecoveryAlert } from '../components/RecoveryAlert';
import {
  CLONE_REQUEST_CONTENT_TYPE,
  CLONE_REQUEST_READ_CONTENT_TYPE,
  CLONE_RESPONSE_CONTENT_TYPE,
  SUBJECT_APPROVAL,
  SUBJECT_REQUEST,
} from './crypto/pairing';

const PAIR_PATH = '/pair';

export const deviceSurfaces: {
  /** Where the pre-auth pairing screen lives; the sign-in page links to it. */
  pairing: NonNullable<Deployment['pairing']>;
  /** The pairing screen's route, for authRoutes. */
  authRoute: { path: string; element: ReactNode };
  /** The device list in Settings: who may open the mailbox, and removing them. */
  devices: NonNullable<Deployment['devices']>;
  /** The pairing payloads, which the mail UI must recognise and never show as attachments. */
  internalAttachmentTypes: string[];
  /** The pairing messages, kept out of the mail folders. */
  controlSubjects: string[];
  /**
   * The row that announces a waiting request. An approval is absent on purpose: it answers a
   * request THIS device made, and the pairing screen that is waiting for it picks it up itself.
   * The words are the shell's sentence about a stranger, so they say what is being asked and how
   * many are asking, and nothing the requester supplied.
   */
  inboxNotice: InboxNotice;
  /** A device waiting to join without approval, for the top of the inbox (accountNotice). */
  recoveryAlert: typeof RecoveryAlert;
} = {
  pairing: { path: PAIR_PATH },
  authRoute: { path: PAIR_PATH, element: <PairDevice /> },
  devices: DeviceManager,
  internalAttachmentTypes: [CLONE_REQUEST_CONTENT_TYPE, CLONE_REQUEST_READ_CONTENT_TYPE, CLONE_RESPONSE_CONTENT_TYPE],
  controlSubjects: [SUBJECT_REQUEST, SUBJECT_APPROVAL],
  inboxNotice: {
    subject: SUBJECT_REQUEST,
    icon: 'monitor',
    title: 'Device requests',
    summary: n => (n === 1
      ? 'A device is asking to use this account.'
      : `${n} devices are asking to use this account.`),
    view: DeviceRequests,
  },
  recoveryAlert: RecoveryAlert,
};
