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
