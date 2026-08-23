package buildinfo

import (
	"runtime/debug"
	"testing"
)

func bi(mainVersion string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main:     debug.Module{Version: mainVersion},
		Settings: settings,
	}
}

// TestStampedVersionWins keeps `make build` authoritative. git describe knows about tags, distance
// and dirtiness, which is strictly more than the module system can tell us.
func TestStampedVersionWins(t *testing.T) {
	got := resolve("v0.6.0-2-g077cec5-dirty", bi("v0.2.0"))
	if got != "v0.6.0-2-g077cec5-dirty" {
		t.Errorf("got %q, want the ldflags value", got)
	}
}

// TestGoInstallReportsTheModuleVersion is the bug this fixes. `go install module@latest` applies no
// ldflags, so main.version keeps its "dev" default and every installed binary reported "dev".
func TestGoInstallReportsTheModuleVersion(t *testing.T) {
	if got := resolve("dev", bi("v0.2.0")); got != "v0.2.0" {
		t.Errorf("got %q, want v0.2.0", got)
	}
	// Empty is the same situation as "dev" — a binary whose ldflags were never applied.
	if got := resolve("", bi("v0.2.0")); got != "v0.2.0" {
		t.Errorf("got %q, want v0.2.0", got)
	}
}

// TestDevelFallsBackToTheCommit covers `go build` inside a checkout: the module version is the
// placeholder "(devel)", which is worth nothing, but Go stamps the commit alongside it.
func TestDevelFallsBackToTheCommit(t *testing.T) {
	got := resolve("dev", bi("(devel)",
		debug.BuildSetting{Key: "vcs.revision", Value: "077cec56aaea1234567890"},
		debug.BuildSetting{Key: "vcs.modified", Value: "false"},
	))
	if got != "077cec56aaea" {
		t.Errorf("got %q, want the short commit", got)
	}
}

// TestDirtyTreeIsMarked matters for an operator comparing a running binary against a commit: a
// build with uncommitted changes is not that commit, and saying so plainly avoids a confusing hour.
func TestDirtyTreeIsMarked(t *testing.T) {
	got := resolve("dev", bi("(devel)",
		debug.BuildSetting{Key: "vcs.revision", Value: "abcdef123456"},
		debug.BuildSetting{Key: "vcs.modified", Value: "true"},
	))
	if got != "abcdef123456-dirty" {
		t.Errorf("got %q, want the commit marked dirty", got)
	}
}

// TestNoInformationStaysHonest: with nothing to go on, report "dev" rather than inventing a
// version. A wrong version is worse than an obviously absent one.
func TestNoInformationStaysHonest(t *testing.T) {
	if got := resolve("dev", bi("(devel)")); got != "dev" {
		t.Errorf("got %q, want dev", got)
	}
	if got := resolve("dev", nil); got != "dev" {
		t.Errorf("got %q, want dev", got)
	}
	if got := resolve("", nil); got != "dev" {
		t.Errorf("got %q, want dev", got)
	}
}
