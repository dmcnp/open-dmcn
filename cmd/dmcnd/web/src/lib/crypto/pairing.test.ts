// Browser half of the device-pairing known-answer vectors. The Go half is
// internal/core/pairing/parityvector_test.go (clone request/response payloads, the self-signed
// ephemeral record) and goldenSAS in pairing_test.go (the confirmation code), with the same
// constants. These are the values the new device produces on its own and the fleet or the
// approving device verifies; change either side and one suite goes red.
//
// Fixed inputs: Ed25519 seed 32x0x0b (public key below), X25519 public 32x0x08 / private 32x0x0d,
// device id 16x0x03, created 1700000000; request keys 32x0x01 / 32x0x02, label "vector device",
// requested at 1700000000; ephemeral address pair-0102030405060708@pairing.local, one relay hint,
// now = 1700000000. Ed25519 signing is deterministic, so the signed record is a fixed byte string.

import { describe, it, expect } from 'vitest';
import {
  confirmationCode, splitConfirmationCode, cloneRequestAttachment, cloneResponseAttachment,
  extractCloneRequest, extractCloneResponse, buildEphemeralRecord,
} from './pairing';
import type { IdentityKeyPair } from './keys';
import type { AttachmentInput, DecryptedAttachment } from './split';

const VEC = {
  ed25519Pub: '66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a',
  cloneReq: '0a200101010101010101010101010101010101010101010101010101010101010101122002020202020202020202020202020202020202020202020202020202020202021a1003030303030303030303030303030303220d766563746f72206465766963652880e2cfaa06',
  cloneResp: '0a15766563746f72407061726974792e6578616d706c65122066be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a1a400b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a222008080808080808080808080808080808080808080808080808080808080808082a200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3210030303030303030303030303030303033880e2cfaa06',
  ephemeralRec: '08011223706169722d303130323033303430353036303730384070616972696e672e6c6f63616c1a2066be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa063084e9cfaa063a5c2f646e73342f72656c61792e7061726974792e6578616d706c652f7463702f373430302f7032702f313244334b6f6f574e6e55315332424d6e636247705050715768505a51514b4e744e6d4835596e4361487576746936787a56624c5240abb730ff19358cf4ccdf57c5581f1885509dbf22ebfd0a2782248771058f82c25707596dfa9c6d66d96e2bb53893c0bd334df0d9ce81323f16646a7edfa93004d00101',
  relayHint: '/dns4/relay.parity.example/tcp/7400/p2p/12D3KooWNnU1S2BMncbGpPPqWhPZQQKNtNmH5YnCaHuvti6xzVbL',
  sas: '2309-4949-8238', // goldenSAS in Go, for vector@parity.example with keys 32x0x01 / 32x0x02
};

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map(h => parseInt(h, 16)));
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const concat = (a: Uint8Array, b: Uint8Array) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const asDecrypted = (a: AttachmentInput): DecryptedAttachment => ({ filename: a.filename, contentType: a.contentType, content: a.content, contentId: '', disposition: '' });

const kp: IdentityKeyPair = {
  ed25519Public: unhex(VEC.ed25519Pub),
  ed25519Private: concat(fill(32, 0x0b), unhex(VEC.ed25519Pub)), // seed || public, the Go layout
  x25519Public: fill(32, 0x08),
  x25519Private: fill(32, 0x0d),
  deviceId: fill(16, 0x03),
  createdAt: 1_700_000_000,
};

describe('confirmation code (Go pairing.ConfirmationCode)', () => {
  it('reproduces goldenSAS', async () => {
    expect(await confirmationCode('vector@parity.example', fill(32, 0x01), fill(32, 0x02))).toBe(VEC.sas);
  });

  // The approving device shows `shown` and makes the person type `typed`; the two halves
  // have to rejoin into exactly the code the new device displays.
  it('splits into the shown groups and the typed last one', () => {
    expect(splitConfirmationCode(VEC.sas)).toEqual({ shown: '2309-4949', typed: '8238' });
    const { shown, typed } = splitConfirmationCode(VEC.sas);
    expect(`${shown}-${typed}`).toBe(VEC.sas);
  });
});

describe('clone request (Go pairing.MarshalCloneRequest)', () => {
  it('encodes to the pinned bytes and reads back', async () => {
    const eph: IdentityKeyPair = { ...kp, ed25519Public: fill(32, 0x01), x25519Public: fill(32, 0x02) };
    const a = await cloneRequestAttachment(eph, 'vector device', 1_700_000_000);
    expect(a.contentType).toBe('application/x-dmcn-clone-request');
    expect(hex(a.content)).toBe(VEC.cloneReq);
    const back = await extractCloneRequest([asDecrypted(a)]);
    expect(back?.label).toBe('vector device');
    expect(back?.requestedAt).toBe(1_700_000_000);
    expect(hex(back!.ephemeralEd25519Pub)).toBe('01'.repeat(32));
    expect(hex(back!.deviceId)).toBe('03'.repeat(16));
  });
});

describe('clone response (Go pairing.MarshalCloneResponse)', () => {
  it('encodes the key bundle to the pinned bytes and reads back', async () => {
    const a = await cloneResponseAttachment(kp, 'vector@parity.example');
    expect(a.contentType).toBe('application/x-dmcn-clone-response');
    expect(hex(a.content)).toBe(VEC.cloneResp);
    const back = await extractCloneResponse([asDecrypted(a)]);
    expect(hex(back!.ed25519Private)).toBe(hex(kp.ed25519Private));
    expect(hex(back!.x25519Private)).toBe('0d'.repeat(32));
    expect(back!.createdAt).toBe(1_700_000_000);
  });
});

describe('ephemeral record (Go pairing.NewEphemeralRecord)', () => {
  it('self-signs to the pinned bytes — signable bytes, context tag and signature all agree', async () => {
    const rec = await buildEphemeralRecord('pair-0102030405060708@pairing.local', kp, VEC.relayHint, 1_700_000_000);
    expect(hex(rec)).toBe(VEC.ephemeralRec);
  });
});
