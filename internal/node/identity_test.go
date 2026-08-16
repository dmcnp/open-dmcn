package node_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/node"
)

func TestLoadOrCreateIdentityKeyCreateAndReload(t *testing.T) {
	// Nested path exercises directory creation.
	path := filepath.Join(t.TempDir(), "keys", "node1.key")

	priv1, err := node.LoadOrCreateIdentityKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file permissions = %o, want 600", perm)
	}

	priv2, err := node.LoadOrCreateIdentityKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	id1, _ := peer.IDFromPrivateKey(priv1)
	id2, _ := peer.IDFromPrivateKey(priv2)
	if id1 != id2 {
		t.Errorf("peer ID changed across reload: %s != %s", id1, id2)
	}

	// No temp files left behind.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".identity-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestLoadOrCreateIdentityKeyCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	garbage := []byte("this is not a marshaled libp2p private key")
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	_, err := node.LoadOrCreateIdentityKey(path)
	if err == nil {
		t.Fatal("expected error for corrupt key file, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the path %q: %v", path, err)
	}

	// The corrupt file must not be silently overwritten.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reread: %v", err)
	}
	if string(got) != string(garbage) {
		t.Error("corrupt key file was modified; it should be left untouched")
	}
}

func TestLoadOrCreateIdentityKeyConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "shared.key")

	const n = 16
	var wg sync.WaitGroup
	ids := make([]peer.ID, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			priv, err := node.LoadOrCreateIdentityKey(path)
			if err != nil {
				errs[i] = err
				return
			}
			ids[i], errs[i] = peer.IDFromPrivateKey(priv)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("concurrent callers disagree on peer ID: %s != %s", ids[i], ids[0])
		}
	}
}

func TestWaitForPeersTimesOutWhenIsolated(t *testing.T) {
	// A node with no peers never populates its routing table,
	// so WaitForPeers must return an error rather than block forever.
	n, err := node.New(context.Background(), node.Config{AllowedPeers: []string{"*"}, ListenAddr: "/ip4/127.0.0.1/tcp/0"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer n.Close()

	if err := n.WaitForPeers(context.Background(), 200*time.Millisecond); err == nil {
		t.Fatal("expected timeout error waiting for peers on an isolated node")
	}
}

func TestNodePersistentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	cfg := node.Config{AllowedPeers: []string{"*"},
		ListenAddr:      "/ip4/127.0.0.1/tcp/0",
		IdentityKeyPath: path,
	}

	ctx := context.Background()

	n1, err := node.New(ctx, cfg)
	if err != nil {
		t.Fatalf("first node: %v", err)
	}
	id1 := n1.PeerID()
	n1.Close()

	n2, err := node.New(ctx, cfg)
	if err != nil {
		t.Fatalf("second node: %v", err)
	}
	id2 := n2.PeerID()
	n2.Close()

	if id1 != id2 {
		t.Errorf("peer ID not stable across restart: %s != %s", id1, id2)
	}
}
