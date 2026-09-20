// Asking each home relay to re-key the mailbox after a rotation.
//
// The op carries no parameters. It authenticates like any other mailbox call, and the relay
// derives the PREVIOUS mailbox key from the identity record's own verified rotation chain — so
// there is nothing here a caller could set to name someone else's mailbox.
//
// It must run AFTER the rotated record is published, because a relay that has not yet seen the
// record has no chain to derive that key from.
import { postJSONAs } from './client';
import { mailboxProof } from './mailboxProof';
import type { WorkingKeys } from '../crypto/workingKeys';

interface ChallengeResp { correlation_id: string; nonce: string }

export interface RenameResult {
  complete: boolean;
  moved_messages: number;
  moved_storage: number;
  prev_rx_hex: string;
}

/**
 * Re-key this account's mailbox on its home relays.
 *
 * The keys passed are the NEW ones: the relay resolves the current record to authenticate, and
 * the record it resolves is the rotated one. Calling with the old keys would authenticate against
 * a record that no longer exists.
 *
 * Safe to repeat. Every move is write-then-delete and idempotent, so a call interrupted part-way
 * is finished by another rather than repaired — which is why the ceremony can retry it without
 * tracking how far it got.
 */
export async function renameMailbox(keys: WorkingKeys): Promise<RenameResult> {
  const ch = await postJSONAs<ChallengeResp>(undefined, '/api/v1/mailbox/challenge', { op: 'rename' });
  return postJSONAs<RenameResult>(undefined, '/api/v1/mailbox/complete', {
    correlation_id: ch.correlation_id,
    ...(await mailboxProof(keys, ch.nonce)),
  });
}
