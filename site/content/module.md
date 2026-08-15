---
title: Go module
description: dmcn.dev/open-dmcn is the canonical Go import path for the DMCN Protocol reference implementation and its generated protobuf package.
---

# The Go module

The reference implementation is a Go module published under a **vanity import path** on this
domain:

```
dmcn.dev/open-dmcn
```

```bash
go get dmcn.dev/open-dmcn
```

```go
import "dmcn.dev/open-dmcn/dmcnpb"
```

## Why an import path on this domain

An import path is a promise about where something lives, and hosting a promise on someone
else's namespace makes it theirs to break. `github.com/<account>/open-dmcn` binds every
consumer's source code to one account on one forge: moving the repository between accounts,
transferring it to an organisation, or leaving GitHub entirely would invalidate every import
line in every downstream project.

Anchoring the path to `dmcn.dev` removes that coupling. This page serves the `go-import` meta
tag that tells the Go toolchain where the source currently is, so relocating the repository
is a one-line change here and a no-op everywhere else. The protocol's identity is the
domain; the forge is an implementation detail.

## What is in it

The module's public surface is deliberately narrow.

| Package | Stability | Contents |
|---|---|---|
| `dmcnpb` | the compatibility contract | generated protobuf types for `dmcn.identity`, `dmcn.message`, `dmcn.relay` and `dmcn.bridge` |
| `internal/…` | **no API-stability promise** | the reference implementation itself |
| `cmd/dmcnd` | binary | the single-binary reference daemon |
| `cmd/dmcndcli` | binary | the operator CLI |

The wire schema is what compatibility is measured against — not the Go API. `internal/`
packages are visible in the repository so the implementation can be read alongside the
[specification](/spec), but they are not importable and carry no stability guarantee.
Breaking checks run at package level, and the proto package names are load-bearing for
reflection-based consumers, so they never change.

## Documentation

Package documentation is published on
[pkg.go.dev](https://pkg.go.dev/dmcn.dev/open-dmcn), and the `go-source` meta tag on this
page wires its source links back to the repository at the right revision.
