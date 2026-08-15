.PHONY: build build-web build-daemon proto proto-web test test-cover lint vet clean tidy \
        site site-serve site-test site-check

# Version string embedded at build time (best-effort git describe).
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

WEB := cmd/dmcnd/web

# build produces the self-contained daemon (bin/dmcnd) + the operator CLI (bin/dmcndcli). It first
# builds the embedded web SPA (so //go:embed web/dist is fresh), then compiles the Go binaries.
build: build-web build-daemon build-cli

build-daemon:
	go build $(LDFLAGS) -o bin/dmcnd ./cmd/dmcnd

# build-cli compiles the standalone operator tool (peer-id + _dmcn DNS record).
build-cli:
	go build $(LDFLAGS) -o bin/dmcndcli ./cmd/dmcndcli

# build-web installs frontend deps and produces cmd/dmcnd/web/dist (embedded by the daemon).
build-web:
	cd $(WEB) && npm ci && npm run build

# proto-web regenerates the browser protobuf bundle (dmcn.js) from the CORE protos only —
# identity + message + relay. It MUST list every proto in the bundle; a partial run silently
# drops whole namespaces. bridge.js is a separate single-proto module — regenerate it manually.
PBJS = cd $(WEB) && npx -y -p protobufjs-cli@1.1.3 pbjs -t static-module -w es6 -p ../../../proto
PBTS = cd $(WEB) && npx -y -p protobufjs-cli@1.1.3 pbts
CORE_PROTOS = ../../../proto/identity.proto ../../../proto/message.proto ../../../proto/relay.proto

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
# self-hosted deployment would send. http://localhost:8080
site-serve: site
	cd $(SITE) && GOWORK=off go run . serve -dir ../docs -addr :8080 -dev

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
	rm -rf bin/ $(WEB)/dist $(WEB)/node_modules coverage*.txt
