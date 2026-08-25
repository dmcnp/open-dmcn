.PHONY: build build-web build-daemon build-cli build-release proto proto-web test test-cover lint vet clean tidy \
        site site-serve site-test site-check

# Version string embedded at build time (best-effort git describe).
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
# Release builds additionally strip the symbol table and DWARF, which is most of the
# binary size and none of the behaviour.
RELEASE_LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
BINARIES  := dmcnd dmcndcli
DIST      := dist

WEB := cmd/dmcnd/web

# build produces the self-contained daemon (bin/dmcnd) + the operator CLI (bin/dmcndcli). It first
# builds the embedded web SPA (so //go:embed web/dist is fresh), then compiles the Go binaries.
build: build-web build-daemon build-cli

build-daemon:
	go build $(LDFLAGS) -o bin/dmcnd ./cmd/dmcnd

# build-cli compiles the standalone operator tool (peer-id + _dmcn DNS record).
build-cli:
	go build $(LDFLAGS) -o bin/dmcndcli ./cmd/dmcndcli

# build-release cross-compiles both binaries for every supported platform into dist/, as ONE
# ARCHIVE PER BINARY plus a SHA256SUMS covering them all.
#
# Separate archives, not one combined: the daemon and the operator CLI are meant to live on
# different machines. dmcndcli holds the domain root key and belongs on the machine you
# administer from — ideally one that stays offline — while dmcnd runs on the internet-facing
# host. Shipping them together would put the root-key tool in the server download and quietly
# argue against the posture the whole live-domain design exists to create.
#
# CGO is off, so every binary is a single static file with no runtime dependency — which is
# also what lets the container image use a distroless base. The checksums matter here more
# than usual: one of these tools mints and holds your domain's trust anchor.
#
# Uses the COMMITTED web SPA rather than rebuilding it, so a release ships exactly what is in
# the tree and needs no Node toolchain. Run `make build-web` first if you changed the frontend
# and have not committed cmd/dmcnd/web/dist.
build-release:
	@rm -rf $(DIST)
	@mkdir -p $(DIST)
	@for platform in $(PLATFORMS); do \
	  os=$${platform%/*}; arch=$${platform#*/}; ext=""; \
	  if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
	  for bin in $(BINARIES); do \
	    echo "building $$bin $$os/$$arch"; \
	    dir="$(DIST)/$$bin-$$os-$$arch"; mkdir -p "$$dir"; \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath $(RELEASE_LDFLAGS) -o "$$dir/$$bin$$ext" ./cmd/$$bin || exit 1; \
	    cp LICENSE NOTICE README.md "$$dir/"; \
	    if [ "$$os" = "windows" ] && command -v zip >/dev/null 2>&1; then \
	      (cd $(DIST) && zip -qr "$$bin-$(VERSION)-$$os-$$arch.zip" "$$bin-$$os-$$arch"); \
	    else \
	      tar -czf "$(DIST)/$$bin-$(VERSION)-$$os-$$arch.tar.gz" -C $(DIST) "$$bin-$$os-$$arch"; \
	    fi; \
	    rm -rf "$$dir"; \
	  done; \
	done
	@cd $(DIST) && for f in *.tar.gz *.zip; do [ -f "$$f" ] || continue; \
	  sha256sum "$$f" 2>/dev/null || shasum -a 256 "$$f"; \
	done > SHA256SUMS
	@echo; ls -1 $(DIST)

# build-web installs frontend deps and produces cmd/dmcnd/web/dist (embedded by the daemon).
build-web:
	cd $(WEB) && npm ci && npm run build

# proto-web regenerates the browser protobuf bundle (dmcn.js). It MUST list every proto in the
# bundle; a partial run silently drops whole namespaces.
#
# bridge.proto is in here deliberately. It used to be a separate hand-regenerated bridge.js, which
# meant it was generated from bridge.proto ALONE — so the dmcn.identity.Credential it imports never
# resolved, and the browser could not see the bridge credential at all. One bundle, one command, no
# "regenerate it manually" step to forget.
PBJS = cd $(WEB) && npx -y -p protobufjs-cli@1.1.3 pbjs -t static-module -w es6 -p ../../../proto
PBTS = cd $(WEB) && npx -y -p protobufjs-cli@1.1.3 pbts
CORE_PROTOS = ../../../proto/identity.proto ../../../proto/message.proto ../../../proto/relay.proto ../../../proto/bridge.proto

proto-web:
	$(PBJS) -o src/lib/proto/dmcn.js $(CORE_PROTOS)
	$(PBTS) -o src/lib/proto/dmcn.d.ts src/lib/proto/dmcn.js

# proto regenerates the Go bindings (dmcnpb) from the core schema. Requires the buf CLI.
proto:
	buf generate

# ----------------------------------------------------------------------------
# dmcn.dev — the protocol's documentation site.
#
# site/ is a SEPARATE Go module (hence GOWORK=off), so its markdown renderer
# never enters this module's dependency graph and site/ is excluded from the
# module zip that `go get` downloads.
#
# The rendered output in docs/ is COMMITTED, and GitHub Pages publishes it
# straight from the branch — publishing therefore depends on no CI at all, and
# survives a repository transfer untouched. The cost of committing generated
# files is that they can go stale, which is what site-check exists to prevent.
# ----------------------------------------------------------------------------
SITE := site

# site renders the whole site into docs/. The spec page is rendered from
# SPEC.md itself, so there is never a second copy to drift.
site:
	cd $(SITE) && GOWORK=off go run . build -out ../docs

# site-serve previews docs/ locally with the same security headers the
# self-hosted deployment would send. http://localhost:8081 — deliberately not :8080,
# which dmcnd dev mode now uses, so the site preview and the daemon can run together.
site-serve: site
	cd $(SITE) && GOWORK=off go run . serve -dir ../docs -addr :8081 -dev

site-test:
	cd $(SITE) && GOWORK=off go test ./... -timeout 60s

# site-check fails if docs/ is not exactly what site/ generates right now —
# i.e. if someone edited content or templates and forgot to re-render, or
# edited the generated HTML by hand. Wired into `test` so stale output cannot
# reach the published site.
site-check: site site-test
	@if [ -n "$$(git status --porcelain -- docs)" ]; then \
		echo "docs/ is out of date — run 'make site' and commit the result:"; \
		git --no-pager status --short -- docs; \
		exit 1; \
	fi

test: site-check
	go test ./... -timeout 120s

test-cover:
	go test ./... -cover -timeout 120s

vet:
	go vet ./...

lint: vet
	buf lint

# tidy runs go mod tidy (use GOWORK=off if resolving the published module).
tidy:
	go mod tidy

clean:
	rm -rf bin/ $(DIST)/ $(WEB)/dist $(WEB)/node_modules coverage*.txt
