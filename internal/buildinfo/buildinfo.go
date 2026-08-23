// Package buildinfo resolves the version string a binary reports.
//
// It exists because there are two ways these binaries get built and only one of them runs the
// Makefile. `make build` stamps -X main.version with `git describe`, which gives the nicest answer
// (a tag, plus commits-since and -dirty). But `go install dmcn.dev/open-dmcn/cmd/dmcnd@latest` —
// the way the quickstart tells people to install — applies no ldflags at all, so the variable kept
// its "dev" default and every installed binary reported `dmcnd dev`.
//
// Go already embeds what is needed in both cases: the module version for a `go install
// module@version`, and VCS stamps for a build inside a checkout. This reads those.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Version returns the version to report. stamped is the -X main.version value, used verbatim when
// the Makefile set it; everything else is the fallback for a build that did not go through it.
//
// Order matters: the ldflags value is the most specific (it knows about tags and dirtiness), the
// module version is authoritative for an installed binary, and the VCS revision is the last resort
// for `go build` inside a clone.
func Version(stamped string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return resolve(stamped, bi)
}

// resolve is Version's logic with the build info passed in, so it can be tested against each of
// the build shapes rather than only whichever one the test binary happens to have.
func resolve(stamped string, bi *debug.BuildInfo) string {
	if stamped != "" && stamped != "dev" {
		return stamped
	}
	if bi == nil {
		return fallback(stamped)
	}
	// A binary installed as module@version carries that version. "(devel)" means it was built
	// from a directory rather than fetched, so it says nothing useful.
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	// Built from a checkout: Go stamps the commit and whether the tree was dirty.
	var rev, modified string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if rev == "" {
		return fallback(stamped)
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if modified == "true" {
		return rev + "-dirty"
	}
	return rev
}

// fallback keeps whatever the caller had rather than inventing something, so a binary built in a
// way nobody anticipated reports "dev" instead of a confident lie.
func fallback(stamped string) string {
	if strings.TrimSpace(stamped) == "" {
		return "dev"
	}
	return stamped
}
