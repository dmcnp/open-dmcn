# dmcn.dev

The DMCN Protocol's home: the specification, a quickstart, an FAQ, and the Go vanity import
path for this module.

```bash
make site         # render into ../docs
make site-serve   # preview on localhost:8081 with production headers
make site-test    # unit tests
make site-check   # fail if ../docs is not what site/ generates (wired into `make test`)
```

## How it is put together

`site/` is a **separate Go module**. That keeps goldmark out of the protocol module's
dependency graph, and — because `go mod` excludes any directory containing its own `go.mod`
from the parent module's zip — keeps this whole directory out of what `go get` downloads.
Everything here runs with `GOWORK=off`.

| Path | What it is |
|---|---|
| `content/*.md` | the authored pages (front matter + markdown) |
| `templates/` | layout, header, footer, and the three page shapes |
| `static/` | design system copied from the DMCN marketing sites, plus `docs.css` |
| `../SPEC.md` | rendered directly as `/spec` — **not** copied here |
| `../docs/` | generated output, committed, served by GitHub Pages |

Two properties are deliberate and tested:

- **No third-party subresources.** Fonts are self-hosted, icons are inlined SVG, and there
  is no JavaScript at all — which is what lets the CSP say `script-src 'none'`.
- **No second copy of the spec.** `/spec` renders `SPEC.md` itself, so the site cannot
  drift from the reference implementation.

## Hosting

`docs/` is a plain static directory, which keeps hosting a deployment decision rather than
an architectural one:

- **GitHub Pages** (current): publishes `docs/` straight from the branch. No CI involved, so
  nothing to re-enable after a repository transfer. Its one limitation is that it cannot
  send custom headers — `_headers` is written for hosts that honour it (Cloudflare Pages,
  Netlify) and is inert on Pages.
- **Self-hosted**: `site serve -dir docs` serves the identical bytes with the full header
  set (CSP, nosniff, `X-Frame-Options`, `Referrer-Policy`, HSTS) behind a TLS terminator.

## The vanity import path

The module is imported as `dmcn.dev/open-dmcn`, not as a `github.com/…` path, so relocating
the repository between accounts, organisations or forges never invalidates a downstream
import. The `go-import` meta tag is served on both `/open-dmcn/` and `/` — the go command
asks for the full import path first and then trims path elements, so the module page answers
directly and the root answers as a fallback.

**Two things must agree**, and `TestVanityPath` fails in both directions if they do not:

1. `../go.mod` declares `module dmcn.dev/open-dmcn`
2. `vanityActive = true` in `main.go`

While they disagree, the module page says the path is not active yet and the build prints a
warning — serving the meta tag alone is not enough, because `go get` fetches the repository
and then rejects it for declaring a different module path.

### Moving the repository

Change `repoURL` in `main.go`, run `make site`, commit. Nothing else moves: the import path
is anchored to the domain, not to the forge.
