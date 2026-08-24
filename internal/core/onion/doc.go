// Package onion implements DMCN onion routing (SPEC.md §6): per-hop
// layered encryption (SealLayer/OpenLayer), fixed 3-hop packet build/peel
// (BuildOnion/PeelOnion), and diversity-aware route selection (SelectRoute).
//
// # Privacy properties provided
//
//   - Layered confidentiality: each hop learns only its predecessor and successor
//     (entry: sender+hop2; middle: hop1+hop3; exit: hop2+recipient). No single
//     relay links sender to recipient.
//   - Per-hop unlinkability: every layer uses a fresh ephemeral X25519 key, so a
//     packet looks unrelated across hops.
//   - Size-class padding: the innermost (delivery) layer is bucketed to a size
//     class (frameLayer, classes 1 KB–36 MB, the top sitting just above the ~35 MB
//     message ceiling), hiding the message size among all same-class messages. Outer
//     (forwarding) layers add only routing overhead — they are NOT re-bucketed — so
//     a 3-hop message is ~3× its size class on the wire (the inherent cost of
//     relaying it three times), not a per-hop bucket multiplication.
//   - Optional per-hop timing jitter (relay.WithOnionJitter) blurs simple timing
//     correlation.
//   - Route diversity: distinct peers and (in strict mode) distinct /24 subnets;
//     an optional pinned guard for the entry hop.
//
// # Residual gaps (not yet implemented)
//
//   - Not Sphinx: packets are nested, so they SHRINK hop-to-hop — a global observer
//     can infer position from the decreasing size. Padding is per-layer bucketing,
//     not constant-size-across-hops. Full fixed-size (Sphinx) packets are future
//     work.
//   - No mixing/batching: forwarding is synchronous hop-by-hop (the sender blocks
//     on the chain's ACK). Jitter is a weak substitute for a real mix node that
//     batches + reorders; end-to-end latency still correlates send/deliver.
//   - No cover traffic: there are no dummy packets, so traffic volume is observable.
//   - Guard persistence: SelectRoute can pin a guard, but persisting/rotating it is
//     the caller's job and is NOT done for the ephemeral CLI (each invocation draws
//     fresh). A long-lived client should hold a guard and rotate it ~monthly.
//   - Small-network anonymity: Relaxed mode (dev/3-node cluster) drops subnet
//     diversity, so co-located relays share an operator — the structural property
//     holds but the anonymity set is small until the relay set diversifies.
package onion
