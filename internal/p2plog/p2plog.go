// Package p2plog centralizes how we treat libp2p's internal logging.
//
// libp2p logs through github.com/ipfs/go-log/v2 from background goroutines we
// don't drive — the basichost address manager, identify, autonat, the resource
// manager, etc. Those logs are never returned to us, so we can't route them
// through our own logr logger. They're also redundant: every error from an
// operation we actually invoke (host.Connect, relay streams, fleet resolve ops) is
// returned to and logged by our code. So rather than chase one noisy message
// (e.g. basichost's once-a-minute netlink address-enumeration failure, which is
// harmless because we route via dns4 relay hints, not auto-detected addrs), we
// silence libp2p's internal logger wholesale and rely on our own.
package p2plog

import (
	"os"

	golog "github.com/ipfs/go-log/v2"
)

// Silence raises libp2p's internal (go-log) logging to fatal, suppressing its
// info/warn/error chatter. Call it once at process startup, before any libp2p
// host is created. An explicit GOLOG_LOG_LEVEL in the environment is respected
// as an override (set it to e.g. "debug" or "info" to restore libp2p logging
// when diagnosing a transport problem).
func Silence() {
	if os.Getenv("GOLOG_LOG_LEVEL") != "" {
		return
	}
	golog.SetAllLoggers(golog.LevelFatal)
}
