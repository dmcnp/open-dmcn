package main

// protocol.go builds /protocol/: the technical page. Its first half is prose (content/protocol.md);
// its second half is the wire reference, whose field tables are GENERATED from the protobuf
// descriptors this repository compiles (dmcnpb) and merged with the hand-written notes below.
//
// How it stays honest:
//   - Every message, oneof and enum table is built from the live descriptors. A field without a
//     note, or a note naming a field that no longer exists, is a build error (schemaAudit), so
//     `make site` fails and `make test` (site-check) fails with it. A schema change cannot drift
//     past this page.
//   - The tables that are not protobuf (roles, grants, policy bits, context tags, protocol IDs and
//     frame limits, size classes) are literals here, pinned against the Go source they describe by
//     protocol_tables_test.go.
//
// Scope is the core protocol: what an independent implementation needs to interoperate. Operator
// extensions ride their own schema and are left out (SPEC.md §8).

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// protoSection is one heading of the reference half. referenceSections is the only place a title
// is written: the template asks for each heading by id (refHeading), and the table of contents is
// built from the same list.
type protoSection struct{ ID, Title string }

// specTable is one reference table, rendered by the "spec-table" define as a collapsed
// <details data-ref> block. Mono is the number of LEADING columns set in the mono font.
type specTable struct {
	Ref  string
	Cols []string
	Mono int
	Rows [][]string
}

// opNote annotates one relay op: its auth class and the authorization rule.
type opNote struct{ Class, Auth string }

// protocolData is the reference half of /protocol/.
type protocolData struct {
	Sections []protoSection

	// Generated from the protobuf descriptors.
	IdentityFields specTable
	Tiers          specTable
	EnvelopeFields specTable
	CredFields     specTable
	RotationFields specTable
	HistoryFields  specTable
	RelayOps       specTable

	// Hand-curated (not protobuf), pinned by protocol_tables_test.go.
	WireProtos  specTable
	CredRoles   specTable
	CredGrants  specTable
	DarPolicy   specTable
	CtxTags     specTable
	SizeClasses specTable
}

// referenceSections are the reference half's headings, in page order.
var referenceSections = []protoSection{
	{ID: "identity", Title: "Identity and addressing"},
	{ID: "resolution-detail", Title: "Resolving an address"},
	{ID: "messages", Title: "Messages and encryption"},
	{ID: "wire", Title: "Wire protocols (libp2p)"},
	{ID: "relay-ops", Title: "Relay operations"},
	{ID: "trust", Title: "Credentials and authority"},
	{ID: "signing", Title: "Signing convention"},
	{ID: "onion", Title: "Onion routing (optional)"},
}

// refHeading renders a reference section's h2 from referenceSections. An unknown id fails the
// build, so a template heading can't drift from the table of contents.
func refHeading(id string) (template.HTML, error) {
	for _, s := range referenceSections {
		if s.ID == id {
			return template.HTML(heading("2", id, template.HTMLEscapeString(s.Title))), nil
		}
	}
	return "", fmt.Errorf("no reference section %q", id)
}

// buildProtocol assembles the reference from the descriptors. Any disagreement between the notes
// and the schema is returned as an error: this site is built ahead of time, so the right place to
// stop a stale page is the build.
func buildProtocol() (*protocolData, error) {
	audit := &schemaAudit{}
	d := &protocolData{
		Sections: referenceSections,
		IdentityFields: protoFieldTable("IdentityRecord fields",
			(&dmcnpb.IdentityRecord{}).ProtoReflect().Descriptor(), identityRecordNotes, audit),
		Tiers: protoEnumTable("Verification tiers",
			dmcnpb.VerificationTier(0).Descriptor(), tierNotes, audit),
		EnvelopeFields: protoFieldTable("EncryptedEnvelope fields",
			(&dmcnpb.EncryptedEnvelope{}).ProtoReflect().Descriptor(), envelopeNotes, audit),
		CredFields: protoFieldTable("Credential fields",
			(&dmcnpb.Credential{}).ProtoReflect().Descriptor(), credentialNotes, audit),
		RotationFields: protoFieldTable("RotationEntry fields",
			(&dmcnpb.RotationEntry{}).ProtoReflect().Descriptor(), rotationEntryNotes, audit),
		HistoryFields: protoFieldTable("AddressHistoryRecord fields",
			(&dmcnpb.AddressHistoryRecord{}).ProtoReflect().Descriptor(), historyNotes, audit),
		WireProtos:  wireProtos,
		CredRoles:   credRoles,
		CredGrants:  credGrants,
		DarPolicy:   darPolicy,
		CtxTags:     ctxTags,
		SizeClasses: sizeClasses,
	}
	relayReq := (&dmcnpb.RelayRequest{}).ProtoReflect().Descriptor()
	request := relayReq.Oneofs().ByName("request")
	if request == nil {
		return nil, fmt.Errorf("RelayRequest has no oneof named %q", "request")
	}
	d.RelayOps = protoOneofTable("Relay operations", request, relayOpNotes, audit)
	if len(audit.problems) > 0 {
		sort.Strings(audit.problems)
		return nil, fmt.Errorf("the protocol reference disagrees with the schema; annotate it in site/protocol.go:\n  %s",
			strings.Join(audit.problems, "\n  "))
	}
	return d, nil
}

// ---- Table builders ----

// schemaAudit collects every disagreement between the notes and the schema: an element with no
// note, or a note that matches nothing.
type schemaAudit struct{ problems []string }

func (a *schemaAudit) addf(format string, args ...any) {
	a.problems = append(a.problems, fmt.Sprintf(format, args...))
}

// fieldTypeName renders a field's wire type the way a schema reader expects: scalar kinds
// verbatim, message and enum fields by name, maps as map<k, v>, repeated fields prefixed.
func fieldTypeName(fd protoreflect.FieldDescriptor) string {
	var t string
	switch {
	case fd.IsMap():
		return fmt.Sprintf("map<%s, %s>", fd.MapKey().Kind(), fd.MapValue().Kind())
	case fd.Kind() == protoreflect.MessageKind:
		t = string(fd.Message().Name())
	case fd.Kind() == protoreflect.EnumKind:
		t = string(fd.Enum().Name())
	default:
		t = fd.Kind().String()
	}
	if fd.Cardinality() == protoreflect.Repeated {
		t = "repeated " + t
	}
	return t
}

// reservedRuns scans [1, max] with has() and merges hits into contiguous inclusive runs, whatever
// way the descriptor happens to group its reserved ranges.
// reservedRuns merges reserved ranges (inclusive [lo, hi] pairs, as the descriptor lists them)
// into the fewest runs, so "reserved 11 to 15; reserved 16 to 18;" renders as one 11–18 row.
// Every reserved number is listed, including those above the highest live one.
func reservedRuns(ranges [][2]int) [][2]int {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	var runs [][2]int
	for _, r := range ranges {
		if len(runs) > 0 && r[0] <= runs[len(runs)-1][1]+1 {
			runs[len(runs)-1][1] = max(runs[len(runs)-1][1], r[1])
		} else {
			runs = append(runs, r)
		}
	}
	return runs
}

// reservedFields returns a message's reserved field numbers as inclusive ranges. (FieldRanges
// ends are exclusive; EnumRanges ends are inclusive.)
func reservedFields(md protoreflect.MessageDescriptor) [][2]int {
	var out [][2]int
	for i := 0; i < md.ReservedRanges().Len(); i++ {
		r := md.ReservedRanges().Get(i)
		out = append(out, [2]int{int(r[0]), int(r[1]) - 1})
	}
	return out
}

func reservedValues(ed protoreflect.EnumDescriptor) [][2]int {
	var out [][2]int
	for i := 0; i < ed.ReservedRanges().Len(); i++ {
		r := ed.ReservedRanges().Get(i)
		out = append(out, [2]int{int(r[0]), int(r[1])})
	}
	return out
}

func runLabel(r [2]int) string {
	if r[0] == r[1] {
		return fmt.Sprintf("%d", r[0])
	}
	return fmt.Sprintf("%d–%d", r[0], r[1])
}

type numberedRow struct {
	n     int
	cells []string
}

func sortedTable(t specTable, rows []numberedRow) specTable {
	sort.Slice(rows, func(i, j int) bool { return rows[i].n < rows[j].n })
	for _, r := range rows {
		t.Rows = append(t.Rows, r.cells)
	}
	return t
}

// protoFieldTable builds a field table from a message descriptor. Every field needs a note;
// reserved numbers render as "(reserved)" rows so the gaps read as deliberate.
func protoFieldTable(ref string, md protoreflect.MessageDescriptor, notes map[string]string, audit *schemaAudit) specTable {
	var rows []numberedRow
	seen := make(map[string]bool, len(notes))
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		note, ok := notes[name]
		if !ok {
			audit.addf("%s: field %q (#%d) has no note", md.FullName(), name, fd.Number())
		}
		seen[name] = true
		n := int(fd.Number())
		rows = append(rows, numberedRow{n, []string{fmt.Sprintf("%d", n), name, fieldTypeName(fd), note}})
	}
	for name := range notes {
		if !seen[name] {
			audit.addf("%s: note for %q matches no field", md.FullName(), name)
		}
	}
	for _, r := range reservedRuns(reservedFields(md)) {
		rows = append(rows, numberedRow{r[0], []string{runLabel(r), "(reserved)", "—", "do not reuse"}})
	}
	return sortedTable(specTable{Ref: ref, Cols: []string{"#", "field", "type", "notes"}, Mono: 3}, rows)
}

// protoOneofTable builds the relay operation table from the request oneof. Arm numbers vacated by
// the operator extension protocols are reserved on the parent message, and render as such.
func protoOneofTable(ref string, od protoreflect.OneofDescriptor, notes map[string]opNote, audit *schemaAudit) specTable {
	var rows []numberedRow
	seen := make(map[string]bool, len(notes))
	fields := od.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		name := string(fd.Name())
		note, ok := notes[name]
		if !ok {
			audit.addf("%s: op %q (#%d) has no note", od.FullName(), name, fd.Number())
		}
		seen[name] = true
		n := int(fd.Number())
		rows = append(rows, numberedRow{n, []string{fmt.Sprintf("%d", n), name, note.Class, note.Auth}})
	}
	for name := range notes {
		if !seen[name] {
			audit.addf("%s: note for %q matches no op", od.FullName(), name)
		}
	}
	if md, ok := od.Parent().(protoreflect.MessageDescriptor); ok {
		for _, r := range reservedRuns(reservedFields(md)) {
			rows = append(rows, numberedRow{r[0], []string{runLabel(r), "(reserved)", "—", "vacated by the operator extension protocols; do not reuse"}})
		}
	}
	return sortedTable(specTable{Ref: ref, Cols: []string{"#", "op", "auth class", "authorization"}, Mono: 2}, rows)
}

// protoEnumTable builds a value table from an enum descriptor, including reserved values.
func protoEnumTable(ref string, ed protoreflect.EnumDescriptor, notes map[string]string, audit *schemaAudit) specTable {
	var rows []numberedRow
	seen := make(map[string]bool, len(notes))
	values := ed.Values()
	for i := 0; i < values.Len(); i++ {
		vd := values.Get(i)
		name := string(vd.Name())
		note, ok := notes[name]
		if !ok {
			audit.addf("%s: value %q (%d) has no note", ed.FullName(), name, vd.Number())
		}
		seen[name] = true
		n := int(vd.Number())
		rows = append(rows, numberedRow{n, []string{fmt.Sprintf("%d", n), name, note}})
	}
	for name := range notes {
		if !seen[name] {
			audit.addf("%s: note for %q matches no value", ed.FullName(), name)
		}
	}
	for _, r := range reservedRuns(reservedValues(ed)) {
		rows = append(rows, numberedRow{r[0], []string{runLabel(r), "(reserved)", "do not reuse"}})
	}
	return sortedTable(specTable{Ref: ref, Cols: []string{"value", "name", "meaning"}, Mono: 2}, rows)
}

// ---- Notes merged into the generated tables, keyed by proto field / op / enum-value name ----

var identityRecordNotes = map[string]string{
	"version":                     "record format version",
	"address":                     "local@domain",
	"ed25519_public_key":          "signing key (32 bytes)",
	"x25519_public_key":           "key-agreement key (32 bytes)",
	"created_at":                  "unix seconds",
	"expires_at":                  "unix seconds; 0 = no expiry",
	"relay_hints":                 "reader-facing mirror only, not covered by the self-signature; the authoritative copy lives inside routing_credential (25)",
	"verification_tier":           "trust tier (see the tier table); enforcement is reader-side",
	"attestations":                "web-of-trust attestations (in-person, fingerprint, network, organizational)",
	"self_signature":              "owner Ed25519 (64 bytes) over fields 1–6, 8, 23, 26, 29, 30; ctx dmcn-identity-self-v1\\0",
	"require_onion":               "mailbox requires onion delivery, so relays reject direct stores; covered by the self-signature",
	"address_credential":          "the domain's attestation of the address↔key binding (role address); issued after self-signing, excluded from the self-signature",
	"routing_credential":          "operator-owned routing (role routing) carrying the authoritative relay_hints; excluded from the self-signature so operators can re-point routing without the owner's key",
	"revision":                    "monotonic and owner-signed, so a lower revision can never overwrite a higher one (anti-rollback)",
	"operator_credentials":        "generic operator extension point: operator-attached credentials beyond routing (semantics by role/attributes); excluded from the self-signature; anti-rollback tiebreaks on the newest issued_at across 25 and these",
	"rotation_chain":              "the address's own key-change history: one owner-authorized transition per entry, each signed BOTH by the key it retires and by the key taking over; covered by the self-signature; capped, with the complete history in the address's AddressHistoryRecord",
	"recovery_ed25519_public_key": "owner-held key, kept apart from the active one, that may authorize the next rotation when the active key is lost; covered by the self-signature; empty when none is enrolled",
}

var rotationEntryNotes = map[string]string{
	"version":                        "entry format version",
	"address":                        "the address this transition belongs to; an entry signed for one address can never be replayed into another's history",
	"retired_ed25519_public_key":     "the signing key being given up (32 bytes)",
	"retired_x25519_public_key":      "the mailbox key being vacated (32 bytes)",
	"next_ed25519_public_key":        "the signing key taking over (32 bytes)",
	"next_x25519_public_key":         "the mailbox key taking over (32 bytes)",
	"rotated_at":                     "when the enrolling device attests this transition happened (unix seconds)",
	"next_revision":                  "the IdentityRecord revision this transition mints; must advance",
	"prev_signature_hash":            "SHA-256 of the previous entry's signature, empty at the first rotation; this is what makes truncation visible rather than silent",
	"authorizing_ed25519_public_key": "the key that produced `signature`, either the retiring key or the owner's recovery key (32 bytes)",
	"device_credential":              "the domain's attestation of the enrolled device that authorised this rotation; its issued_at is the device's enrolment date, which a tenure rule is measured against",
	"device_signature":               "64 bytes by the device; a credential alone is public and could be lifted from an earlier transition, so the device signs this one",
	"signature":                      "the outgoing key's consent: 64 bytes by authorizing_ed25519_public_key, ctx dmcn-identity-rotation-v1\\0",
	"next_signature":                 "the incoming key's acceptance, covering the consent: 64 bytes by next_ed25519_public_key, ctx dmcn-identity-rotation-accept-v1\\0",
}

var historyNotes = map[string]string{
	"version": "record format version",
	"domain":  "the address's domain",
	"address": "local@domain; the record is keyed on SHA-256 of this, like the removal record",
	"chain":   "the complete rotation history, oldest first. No container signature: every entry is already signed by the keys it names, so extending the history takes keys the extender must hold. Append-only: a stored history may only be replaced by one that strictly extends it",
}

var tierNotes = map[string]string{
	"VERIFICATION_TIER_UNVERIFIED": "valid but untrusted; addresses register here and still work, and trust is upgraded, never gated at registration",
	"VERIFICATION_TIER_DOMAIN_DNS": "raised by a domain attestation (address credential) chained to the DNS-anchored domain authority",
	"VERIFICATION_TIER_DANE":       "reserved highest tier: DNSSEC/DANE-anchored",
}

var envelopeNotes = map[string]string{
	"version":              "1 = single-blob payload; 2 = split header/body",
	"message_id":           "16-byte UUID",
	"recipients":           "one per recipient device: ephemeral X25519 public key + the wrapped CEK (nonce 12, tag 16)",
	"encrypted_payload":    "v1 only: AES-256-GCM ciphertext of the whole SignedMessage",
	"payload_nonce":        "12 bytes",
	"payload_tag":          "16 bytes",
	"payload_size_class":   "padded size in bytes, one of the size classes",
	"created_at":           "unix seconds",
	"ratchet_pub_key":      "reserved for forward secrecy (protocol v2); zero in v1",
	"encrypted_header":     "v2 split: the sealed SignedHeader, small and listable (sender, subject, snippet, recipient lists, body commitments)",
	"header_nonce":         "12 bytes",
	"header_tag":           "16 bytes",
	"header_size_class":    "padded size in bytes, one of the size classes",
	"encrypted_body":       "v2 split: sealed MessageContent (body + attachments), fetchable separately from the header",
	"body_nonce":           "12 bytes",
	"body_tag":             "16 bytes",
	"body_size_class":      "padded size in bytes, one of the size classes",
	"body_content_address": "cleartext CIDv1 of the body blob, so relays can verify integrity without any key; the authoritative copy is signed inside the header",
}

var credentialNotes = map[string]string{
	"version":        "credential format version",
	"subject":        "Ed25519 public key: the libp2p peer ID for infrastructure and clients, the identity key for addresses",
	"domain":         "the domain this credential is scoped to",
	"address":        "role address only: the attested local@domain",
	"roles":          "what the subject is (see the roles table)",
	"grants":         "what the subject may issue or do (see the grants table)",
	"attributes":     "free-form: multiaddr, ip, x25519 onion key, …",
	"issued_at":      "unix seconds",
	"not_after":      "unix seconds; 0 = never expires",
	"scope":          "authority credentials: subdomain scope (empty = whole domain); delegation can only narrow it",
	"issuer_pub":     "the domain root, or any enrolled issuer whose own grants cover this credential",
	"signature":      "issuer Ed25519 over fields 1–11, 13 and 14; ctx dmcn-credential-v1\\0",
	"relay_hints":    "role routing only: the authoritative operator-signed mailbox relays",
	"effective_from": "unix seconds not-before; the validity window is [effective_from, not_after]",
}

var relayOpNotes = map[string]opNote{
	"store":                {"message", "sender's Ed25519 signature over the envelope; the sender must resolve and pass the recipient domain's policy gates"},
	"fetch_init":           {"message", "opens the mailbox challenge; the relay returns a fresh nonce"},
	"fetch_proof":          {"message", "Ed25519 proof over the relay's nonce with the account key; no passwords, no bearer tokens"},
	"ack":                  {"connection", "credential-admitted federated peer"},
	"ping":                 {"public", "liveness"},
	"mailbox_op":           {"message", "list / body / delete and personal-KV ops, each under a fresh fetch proof"},
	"store_init":           {"message", "chunked store for bodies past the frame cap; sender signature like store, or node role for relay→relay drain handoff"},
	"onion_forward":        {"connection", "credential-admitted federated peer; peel one layer, then forward or deliver"},
	"get_identity":         {"public read", "returns the signed IdentityRecord; the reader verifies it against the DNS anchor"},
	"get_dar":              {"public read", "returns the signed domain authority record; verified against the DNS fingerprint"},
	"get_fleet_roster":     {"public read", "fleet-root-signed node roster"},
	"get_removal":          {"public read", "root-signed address tombstone"},
	"get_blocklist":        {"public read", "root-signed credential revocation list"},
	"get_history":          {"public read", "the address's complete rotation history; self-authenticating through the signatures on its own entries, so serving it discloses nothing a resolver could not verify"},
	"put_record":           {"self-gating", "every record is re-verified on ingest (self-certifying); a fleet may add publisher gating"},
	"get_relay_descriptor": {"public read", "onion descriptor, self-anchored to the relay's peer ID"},
}

// ---- Hand-curated tables: facts that are not protobuf. Pinned by protocol_tables_test.go against
// the constants in internal/; an "(extensions)" row stands for the operator surfaces left out. ----

var wireProtos = specTable{
	Ref:  "libp2p protocol IDs and framing",
	Cols: []string{"protocol ID", "framing", "purpose"},
	Mono: 1,
	Rows: [][]string{
		{"/dmcn/relay/1.0.0", "4-byte big-endian length prefix + protobuf; 4 MB frame cap; bodies chunked past it (to 64 MB)", "the workhorse: store, fetch, mailbox, resolve and onion ops"},
		{"/dmcn/peers/1.0.0", "length-prefixed JSON", "cluster peer discovery: a node returns its configured peer list"},
		{"/dmcn/join/1.0.0", "varint-delimited protobuf", "mutual credential handshake; gates federation, deny-by-default"},
		{"(extensions)", "—", "operator surfaces ride their own protocols and are not part of the core"},
	},
}

var credRoles = specTable{
	Ref:  "Credential roles",
	Cols: []string{"role", "what the subject is"},
	Mono: 1,
	Rows: [][]string{
		{"authority", "a domain's root signing authority (its key anchors the DNS fingerprint)"},
		{"sub-authority", "a delegated issuer enrolled by the root"},
		{"node", "a relay/storage node"},
		{"bridge", "an SMTP bridge"},
		{"client", "an end-user-facing client peer (mints nothing by itself)"},
		{"address", "an attested address↔key binding (rides in IdentityRecord.address_credential)"},
		{"routing", "an operator routing attestation (rides in IdentityRecord.routing_credential)"},
		{"device", "one enrolled device of an account, keyed by a signing key generated on that device and held nowhere else"},
		{"(extensions)", "further roles carry operator-attached entitlements and are not part of the core"},
	},
}

var credGrants = specTable{
	Ref:  "Credential grants",
	Cols: []string{"grant", "what the holder may do"},
	Mono: 1,
	Rows: [][]string{
		{"address", "sign address credentials (attest address↔key bindings)"},
		{"routing", "sign routing credentials (attest mailbox routing)"},
		{"device", "sign device credentials (attest an account's enrolled devices)"},
		{"grant", "delegate: issue credentials that themselves carry grants"},
		{"(extensions)", "further grants cover operator entitlements and fleet administration and are not part of the core"},
	},
}

var darPolicy = specTable{
	Ref:  "Domain policy flags (DAR policy_flags bits)",
	Cols: []string{"bit", "flag", "effect"},
	Mono: 2,
	Rows: [][]string{
		{"1 << 0", "REQUIRE_COUNTERSIGN", "uncountersigned addresses are unusable on this domain; enforced reader-side and at the mailbox fetch gate"},
		{"1 << 2", "REQUIRE_ONION", "every address on the domain must receive via onion delivery"},
		{"1 << 3", "REPLICATE_MAILBOX", "senders store to every listed relay hint instead of first-reachable failover"},
		{"1 << 5", "ALLOW_KEY_ROTATION", "account holders may re-key their own address with an owner-signed rotation chain; off by default"},
		{"1 << 1, 1 << 4, 1 << 6 and up", "(extensions)", "reserved for extensions"},
	},
}

var ctxTags = specTable{
	Ref:  "Signature context tags",
	Cols: []string{"context tag", "signs"},
	Mono: 1,
	Rows: [][]string{
		{"dmcn-identity-self-v1\\0", "IdentityRecord owner self-signature"},
		{"dmcn-identity-rotation-v1\\0", "RotationEntry: the outgoing key's consent"},
		{"dmcn-identity-rotation-accept-v1\\0", "RotationEntry: the incoming key's acceptance"},
		{"dmcn-identity-rotation-device-v1\\0", "RotationEntry: the enrolled device's attestation"},
		{"dmcn-dar-self-v1\\0", "DomainAuthorityRecord root self-signature"},
		{"dmcn-credential-v1\\0", "every Credential"},
		{"dmcn-subauthority-request-v1\\0", "a requester's self-signed sub-authority request"},
		{"dmcn-address-removal-v1\\0", "AddressRemovalRecord (root-signed tombstone)"},
		{"dmcn-key-compromise-v1\\0", "KeyCompromiseRecord"},
		{"dmcn-fleet-roster-v1\\0", "FleetRoster"},
		{"dmcn-msg-header-v1\\0", "SignedHeader (the split-format message header)"},
		{"(extensions)", "further tags sign operator-surface records and are not part of the core"},
	},
}

// sizeClasses: the *_size_class fields carry the padded size itself, in bytes, not an index.
var sizeClasses = specTable{
	Ref:  "Envelope size classes",
	Cols: []string{"size_class value", "bucket"},
	Mono: 1,
	Rows: [][]string{
		{"1024", "1 KB"}, {"4096", "4 KB"}, {"16384", "16 KB"}, {"65536", "64 KB"}, {"262144", "256 KB"},
		{"1048576", "1 MB"},
		{"n × 1048576", "above 1 MB: the payload plus its 4-byte length, rounded up to the next whole MB"},
	},
}
