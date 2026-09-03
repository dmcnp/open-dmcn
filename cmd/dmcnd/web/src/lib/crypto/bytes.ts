// bufferSource adapts a Uint8Array to WebCrypto's BufferSource.
//
// Since TypeScript 5.7 typed arrays carry their buffer type, and BufferSource excludes views
// over a SharedArrayBuffer. A Uint8Array that has passed through any generic helper (a
// protobuf decoder, a subarray, a parameter typed plain `Uint8Array`) is statically
// `Uint8Array<ArrayBufferLike>` and no longer assignable — even though every byte value in this
// client is ArrayBuffer-backed, because nothing here allocates shared memory. This proves that
// fact once, at runtime, instead of casting at every call site: the same view comes back when its
// buffer is an ArrayBuffer, and a copy otherwise.
export function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.buffer instanceof ArrayBuffer) return bytes as Uint8Array<ArrayBuffer>;
  return new Uint8Array(bytes);
}

// Hex encoding. toHex/fromHex are re-exported from keys.ts for its existing importers.
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// randomHex is n random bytes as a 2n-character hex id (tab ids, label ids).
export function randomHex(n: number): string {
  return toHex(crypto.getRandomValues(new Uint8Array(n)));
}
