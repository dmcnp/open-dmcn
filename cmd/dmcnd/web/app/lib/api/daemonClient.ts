// This daemon's own endpoints: self-service registration, and the petition flow a domain uses
// when its root key is kept offline. Neither exists in every deployment — see
// lib/deployment.ts — so they live beside the shared client rather than inside it, and reach
// the network through its apiRequest.

import { apiRequest } from '../../../src/lib/api/client';

// Self-service registration against the local daemon (it is the operator for its own
// domain). The browser generates the keys and self-signs the record; the server attaches a
// routing credential and publishes it. Mints NO session — after "active" the caller logs in
// with the fresh keys (loginWithKeys).
export interface RegisterRequest {
  address: string;
  ed25519_pub: string;
  x25519_pub: string;
  identity_record: string;
  self_signature: string;
}

export interface RegisterResponse {
  status?: string; // "active"
}

export function register(req: RegisterRequest): Promise<RegisterResponse> {
  return apiRequest('POST', '/api/v1/register', req, { skipReauth: true });
}

// --- Mailbox petitions (live self-hosted domains) ----------------------------------------
//
// On a domain whose root key is kept offline the node cannot mint an address, so there is no
// self-service registration. Instead the browser proves it holds a fresh keypair, gets a
// 12-digit code, and the person reads that code to their admin out of band. The admin assigns an
// address with the offline root; the browser learns it by polling and then self-signs a record
// for it. The petitioner never chooses their own address — that is what makes an unclaimed
// petition worthless and lets it simply expire.

export interface PetitionRequest {
  ed25519_pub: string;
  x25519_pub: string;
  proof: string; // Ed25519 over "dmcn-petition-v1\0" ‖ ed25519_pub ‖ x25519_pub
}

export interface PetitionResponse {
  code: string;       // "0428-9173-5560"
  expires_at: string; // RFC3339
}

export function createPetition(req: PetitionRequest): Promise<PetitionResponse> {
  return apiRequest('POST', '/api/v1/petition', req, { skipReauth: true });
}

export interface PetitionStatusResponse {
  status: 'pending' | 'assigned';
  address?: string;    // set once assigned
  expires_at?: string; // set while pending
}

export function petitionStatus(code: string): Promise<PetitionStatusResponse> {
  return apiRequest('GET', `/api/v1/petition/status?code=${encodeURIComponent(code)}`, undefined, { skipReauth: true });
}

export interface PetitionCompleteRequest {
  code: string;
  identity_record: string; // base64 proto, self-signed for the ASSIGNED address
}

export function completePetition(req: PetitionCompleteRequest): Promise<RegisterResponse & { address?: string }> {
  return apiRequest('POST', '/api/v1/petition/complete', req, { skipReauth: true });
}

