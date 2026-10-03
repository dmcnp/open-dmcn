package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// The hand-written tables on /protocol/ (roles, grants, policy bits, signature contexts, protocol
// IDs and frame limits, size classes) describe Go source, not protobuf, so the schema audit can't see them. These tests read the constants
// straight from the source that declares them and fail when a table and the code disagree in
// either direction. They parse the files rather than import them because the site is a separate
// module and cannot import the protocol module's internal packages.

// constDecls parses one source file and returns its package-level constants and variables as
// name → expression.
func constDecls(t *testing.T, rel string) map[string]ast.Expr {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", rel), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	out := map[string]ast.Expr{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if i < len(vs.Values) {
					out[name.Name] = vs.Values[i]
				}
			}
		}
	}
	return out
}

// stringConst resolves a constant to its string value, following same-file aliases
// (GrantAddress = RoleAddress).
func stringConst(t *testing.T, decls map[string]ast.Expr, name string) string {
	t.Helper()
	switch e := decls[name].(type) {
	case *ast.BasicLit:
		v, err := strconv.Unquote(e.Value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	case *ast.Ident:
		return stringConst(t, decls, e.Name)
	default:
		t.Fatalf("%s is not a string constant this test understands (%T)", name, e)
		return ""
	}
}

// tableColumn returns the first column of a table, minus the "(extensions)" placeholder row.
func tableColumn(tab specTable) []string {
	var out []string
	for _, row := range tab.Rows {
		if row[0] != "(extensions)" && !strings.Contains(row[1], "(extensions)") {
			out = append(out, row[0])
		}
	}
	return out
}

func sameSet(t *testing.T, what string, table, code []string) {
	t.Helper()
	sort.Strings(table)
	sort.Strings(code)
	if strings.Join(table, ",") != strings.Join(code, ",") {
		t.Errorf("%s: the /protocol/ table lists %v but the code declares %v", what, table, code)
	}
}

func TestCredentialRolesAndGrantsMatchCode(t *testing.T) {
	decls := constDecls(t, "internal/core/identity/credential.go")
	var roles, grants []string
	for name := range decls {
		switch {
		case strings.HasPrefix(name, "Role"):
			roles = append(roles, stringConst(t, decls, name))
		case strings.HasPrefix(name, "Grant"):
			grants = append(grants, stringConst(t, decls, name))
		}
	}
	sameSet(t, "credential roles", tableColumn(credRoles), roles)
	sameSet(t, "credential grants", tableColumn(credGrants), grants)
}

func TestDomainPolicyFlagsMatchCode(t *testing.T) {
	decls := constDecls(t, "internal/core/identity/dar.go")
	var code []string
	for name, expr := range decls {
		if !strings.HasPrefix(name, "Policy") {
			continue
		}
		shift, ok := expr.(*ast.BinaryExpr)
		if !ok || shift.Op != token.SHL {
			t.Fatalf("%s is not a 1 << n flag", name)
		}
		bit := shift.Y.(*ast.BasicLit).Value
		code = append(code, "1 << "+bit+" "+upperSnake(strings.TrimPrefix(name, "Policy")))
	}
	var table []string
	for _, row := range darPolicy.Rows {
		if row[1] != "(extensions)" {
			table = append(table, row[0]+" "+row[1])
		}
	}
	sameSet(t, "domain policy flags", table, code)
}

func TestSignatureContextTagsMatchCode(t *testing.T) {
	var code []string
	for _, rel := range []string{"internal/core/identity/identity.go", "internal/core/message/split.go"} {
		decls := constDecls(t, rel)
		for name := range decls {
			// Signature contexts are the ctx* constants; aad* labels and HKDF info strings are
			// not signatures and are documented in the message section instead.
			if !strings.HasPrefix(name, "ctx") {
				continue
			}
			v := stringConst(t, decls, name)
			code = append(code, strings.TrimSuffix(v, "\x00"))
		}
	}
	var table []string
	for _, tag := range tableColumn(ctxTags) {
		table = append(table, strings.TrimSuffix(tag, `\0`))
	}
	sameSet(t, "signature context tags", table, code)
}

// upperSnake turns RequireCountersign into REQUIRE_COUNTERSIGN, the way the table names flags.
func upperSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

// intExpr evaluates the constant integer expressions the size limits are written in
// (4 * 1024 * 1024, 1 << 20).
func intExpr(t *testing.T, e ast.Expr) int {
	t.Helper()
	switch e := e.(type) {
	case *ast.BasicLit:
		n, err := strconv.ParseInt(e.Value, 0, 64)
		if err != nil {
			t.Fatalf("%s: %v", e.Value, err)
		}
		return int(n)
	case *ast.ParenExpr:
		return intExpr(t, e.X)
	case *ast.BinaryExpr:
		x, y := intExpr(t, e.X), intExpr(t, e.Y)
		switch e.Op {
		case token.MUL:
			return x * y
		case token.ADD:
			return x + y
		case token.SHL:
			return x << y
		}
	}
	t.Fatalf("not an integer expression this test understands: %T", e)
	return 0
}

func TestSizeClassesMatchCode(t *testing.T) {
	lit, ok := constDecls(t, "internal/core/message/encrypt.go")["sizeClasses"].(*ast.CompositeLit)
	if !ok {
		t.Fatal("sizeClasses in encrypt.go is no longer a slice literal")
	}
	var code []string
	for _, e := range lit.Elts {
		code = append(code, strconv.Itoa(intExpr(t, e)))
	}
	rows := sizeClasses.Rows
	var table []string
	for _, row := range rows[:len(rows)-1] {
		table = append(table, row[0])
	}
	// The order is the protocol (the smallest bucket that fits), so compare as a list, not a set.
	if strings.Join(table, ",") != strings.Join(code, ",") {
		t.Errorf("size classes: the /protocol/ table lists %v but encrypt.go declares %v", table, code)
	}
	if last := code[len(code)-1]; !strings.Contains(rows[len(rows)-1][0], last) {
		t.Errorf("the overflow row should round up in multiples of the largest class, %s", last)
	}
}

// TestWireProtocolsMatchCode: the protocol IDs in the table are exactly the /dmcn/... IDs the Go
// source declares, and the relay row states the frame cap and body ceiling the relay enforces.
func TestWireProtocolsMatchCode(t *testing.T) {
	idRe := regexp.MustCompile(`^/dmcn/[a-z-]+/[0-9]+\.[0-9]+\.[0-9]+$`)
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join("..", "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil && idRe.MatchString(v) {
					found[v] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for id := range found {
		code = append(code, id)
	}
	sameSet(t, "libp2p protocol IDs", tableColumn(wireProtos), code)

	relay := constDecls(t, "internal/relay/relay.go")
	framing := wireProtos.Rows[0][1]
	for _, want := range []string{
		fmt.Sprintf("%d MB frame cap", intExpr(t, relay["maxMessageSize"])>>20),
		fmt.Sprintf("to %d MB", intExpr(t, relay["maxBodySize"])>>20),
	} {
		if !strings.Contains(framing, want) {
			t.Errorf("the /dmcn/relay framing row %q should say %q (internal/relay/relay.go)", framing, want)
		}
	}
}
