---
title: Go module
description: dmcn.dev/open-dmcn is the import path for the Go reference implementation and its generated protobuf types.
---

# The Go module

The reference implementation happens to be written in Go. If you're implementing DMCNP in
something else, you want [the spec](/spec) and `proto/` — not this page.

```
{{module}}
```

```bash
go get {{module}}
```

```go
import "{{module}}/dmcnpb"
```

## Why the import path lives here

An import path says where something lives, and putting that on someone else's namespace makes
it theirs to break. `github.com/<account>/open-dmcn` ties every downstream project to one
account on one host — move the repo, and every import line is wrong.

Anchoring it to `dmcn.dev` fixes that. This page serves the `go-import` meta tag telling the
Go toolchain where the source is right now, so moving the repository is a one-line change
here and nothing anywhere else.

## What's in it

| Package | Stability | Contents |
|---|---|---|
| `dmcnpb` | the compatibility contract | generated types for `dmcn.identity`, `dmcn.message`, `dmcn.relay`, `dmcn.bridge` |
| `internal/…` | **no stability promise** | how this implementation happens to work |
| `cmd/dmcnd` | binary | the reference server |
| `cmd/dmcndcli` | binary | its operator CLI |

Compatibility is measured against the wire schema, not the Go API. The `internal/` packages
are readable so you can check the implementation against the spec, but they aren't importable
and they'll change without warning.

Docs are on [pkg.go.dev]({{module-docs}}), and the `go-source` meta tag on this page wires
its source links back to the right revision.
