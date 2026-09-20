package relay

// Capability tokens this build advertises in PingResponse.capabilities.
//
// A token is a promise about THIS binary, answering the one question a caller cannot get from
// `version`: will this relay accept what I am about to send? The schema and the code that
// honours it deploy separately, and a signed core field is only safe to emit once every reader
// has landed — so a producer asks first rather than guessing from a build string.
//
// Rules for adding one: name what the build DOES, add it in the same change that makes it true,
// and never advertise a feature that is merely compiled in. A wrong token is worse than a
// missing one, because the caller acts on it.
const (
	// CapRotationSchema: this build parses and re-marshals IdentityRecord.rotation_chain and
	// recovery_ed25519_public_key, so a record carrying them verifies here instead of being
	// refused as a bad self-signature.
	//
	// This is the deploy-ordering signal specifically. It says nothing about whether the relay
	// will AUTHORIZE an owner-signed rotation — that is a separate rule with its own token —
	// only that a record carrying the fields is intelligible. An operator rolling the fleet
	// forward watches this to know the readers have landed.
	CapRotationSchema = "rotation-schema"

	// CapRotation: this build ENFORCES the owner-rotation rebind arm, so a record carrying a
	// chain that verifies will be admitted on a domain whose DAR opts in.
	//
	// Separate from CapRotationSchema because the two answer different questions. Schema support
	// says a record carrying the fields is intelligible here — the deploy-ordering signal.
	// This says the relay will act on it. A client about to re-key needs the second: a fleet
	// that merely parses the chain would still refuse the rebind, after the client had already
	// re-wrapped its keystore.
	CapRotation = "rotation"
)

// capabilities returns the tokens this build advertises, newest last.
//
// Deliberately a function over a package-level slice: a caller that mutated a shared slice
// would change what every future Ping claims.
func capabilities() []string {
	return []string{CapRotationSchema, CapRotation}
}
