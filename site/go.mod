// The dmcn.dev site generator is a SEPARATE Go module on purpose.
//
// open-dmcn is consumed as a library (the protobuf package in dmcnpb/), and a
// documentation-site generator has no business appearing in a consumer's module
// graph. Keeping it here means goldmark never becomes a dependency of the
// protocol module, and — because `go mod` excludes any directory containing its
// own go.mod from the parent module's zip — site/ is not shipped to anyone who
// runs `go get` on the protocol.
//
// Build the site with `make site` from the repository root.
module dmcn.dev/open-dmcn/site

go 1.25.0

require github.com/yuin/goldmark v1.8.5
