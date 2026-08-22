// Command site renders and serves dmcn.dev — the home of the DMCN Protocol.
//
// Two modes, one set of bytes:
//
//	site build -out ../docs     render the site to a static directory
//	site serve -dir ../docs     serve that directory with the full header set
//
// `build` output is committed to docs/ and published by GitHub Pages straight
// from the branch, so publishing needs no CI at all. `serve` exists because
// GitHub Pages cannot send custom headers: when dmcn.dev moves behind our own
// TLS terminator, this mode serves the identical directory with the CSP and
// hardening headers the rest of the estate uses. Hosting is therefore a DNS
// decision, never an architecture one.
package main

import (
	"flag"
	"fmt"
	"os"
)

// ----------------------------------------------------------------------------
// Deploy constants — the only values that change when the repository moves.
// ----------------------------------------------------------------------------

const (
	// siteDomain is the vanity domain reserved for the open protocol.
	siteDomain = "dmcn.dev"

	// moduleName is the path segment under siteDomain that the Go module
	// resolves at, so the import path is siteDomain/moduleName/....  It is also
	// the URL of the module's landing page (/open-dmcn).
	moduleName = "open-dmcn"

	// repoURL is where the module actually lives in git. This is the ONE line to
	// change when open-dmcn moves from a personal account to the dmcnp org — the
	// import path stays dmcn.dev/open-dmcn either way, which is the entire point
	// of a vanity path: consumers never edit an import because we moved hosts.
	repoURL = "https://github.com/dmcnp/open-dmcn"

	// repoBranch backs the go-source line-number links used by pkg.go.dev.
	repoBranch = "main"

	// vanityActive records whether the module ACTUALLY declares the vanity path
	// yet — that is, whether ../go.mod says `module dmcn.dev/open-dmcn`.
	//
	// Serving the go-import meta tag is necessary but not sufficient: if the
	// module still declares a github.com/… path, `go get dmcn.dev/open-dmcn`
	// fetches the repository and then rejects it for declaring a different path.
	// While this is false the module page says so plainly and the build warns,
	// so the site cannot quietly advertise an import path that does not work.
	//
	// Flip it to true in the same commit that changes ../go.mod. TestVanityPath
	// fails if the two ever disagree in either direction.
	vanityActive = true

	// The two DMCN-operated services the footer points at. dmcn.dev is the
	// protocol; these are one operator's products built on it.
	consumerURL = "https://get.dmcn.email"
	businessURL = "https://get.dmcnmail.com"
)

// SiteConfig is the deploy-specific data threaded into every page.
type SiteConfig struct {
	Domain      string // dmcn.dev
	BaseURL     string // https://dmcn.dev
	ModuleName  string // open-dmcn        (the URL segment)
	ModulePath  string // dmcn.dev/open-dmcn (the Go import path)
	RepoURL     string
	Branch      string
	ConsumerURL string
	BusinessURL string
}

// Vanity is the go-import/go-source pair a page emits. Non-nil only on the
// pages that carry the Go module meta tags; see vanityPages in build.go.
type Vanity struct {
	Module string // dmcn.dev/open-dmcn
	Repo   string // https://github.com/…/open-dmcn
	Branch string
}

func config() SiteConfig {
	return SiteConfig{
		Domain:      siteDomain,
		BaseURL:     "https://" + siteDomain,
		ModuleName:  moduleName,
		ModulePath:  siteDomain + "/" + moduleName,
		RepoURL:     repoURL,
		Branch:      repoBranch,
		ConsumerURL: consumerURL,
		BusinessURL: businessURL,
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		out := fs.String("out", "../docs", "output directory for the rendered site")
		spec := fs.String("spec", "../SPEC.md", "path to the canonical protocol specification")
		_ = fs.Parse(os.Args[2:])
		if err := build(config(), *out, *spec); err != nil {
			fatal(err)
		}
		fmt.Printf("site: rendered %s → %s\n", siteDomain, *out)

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		dir := fs.String("dir", "../docs", "directory to serve")
		addr := fs.String("addr", ":8081", "listen address")
		dev := fs.Bool("dev", false, "omit HSTS (local preview over plain HTTP)")
		_ = fs.Parse(os.Args[2:])
		if err := serve(*dir, *addr, *dev); err != nil {
			fatal(err)
		}

	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `site — render and serve %s

  site build [-out ../docs] [-spec ../SPEC.md]
  site serve [-dir ../docs] [-addr :8081] [-dev]
`, siteDomain)
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "site:", err)
	os.Exit(1)
}
