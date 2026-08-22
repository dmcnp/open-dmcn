package main

import "testing"

// TestListenURLHost covers the forms a listen address actually takes in config. A bare
// ":8443" or a wildcard bind is not something a reader can paste into a browser, and the
// startup line's whole job is to be pasteable.
func TestListenURLHost(t *testing.T) {
	for _, tc := range []struct{ listen, host, want string }{
		{":8443", "localhost", "localhost:8443"},
		{"0.0.0.0:8443", "localhost", "localhost:8443"},
		{"[::]:8443", "localhost", "localhost:8443"},
		{"127.0.0.1:8443", "localhost", "127.0.0.1:8443"},
		{":443", "mail.example.com", "mail.example.com:443"},
		{":8443", "", "localhost:8443"}, // no domain configured yet
	} {
		if got := listenURLHost(tc.listen, tc.host); got != tc.want {
			t.Errorf("listenURLHost(%q, %q) = %q, want %q", tc.listen, tc.host, got, tc.want)
		}
	}
}

// TestDefaultHTTPListenSplit pins that dev and production listen on different ports, and why:
// dev serves cleartext, and :8443 conventionally means HTTPS. A cold-install run in Aug 2026
// hit exactly this — the browser tried https:// against a plain-HTTP :8443 and the failure
// read as a broken daemon. Collapsing these back to one port reintroduces that.
func TestDefaultHTTPListenSplit(t *testing.T) {
	dev, prod := defaultHTTPListen(true), defaultHTTPListen(false)
	if dev == prod {
		t.Fatalf("dev and production share port %s — dev serves plain HTTP and must not sit on an HTTPS-conventional port", dev)
	}
	if prod != ":8443" {
		t.Errorf("production default = %q, want :8443", prod)
	}
	if dev == ":8443" || dev == ":443" {
		t.Errorf("dev default %q is an HTTPS-conventional port but dev serves cleartext", dev)
	}
}
