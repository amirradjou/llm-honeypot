package sshd

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrCreateHostKey_IsStableAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "host_ed25519")

	first, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	a, b := ssh.FingerprintSHA256(first.PublicKey()), ssh.FingerprintSHA256(second.PublicKey())
	if a != b {
		t.Fatalf("fingerprint changed between calls: %s vs %s", a, b)
	}
	if first.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %s, want %s", first.PublicKey().Type(), ssh.KeyAlgoED25519)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("host key perm = %o, want 0600", perm)
	}
}

func TestLoadOrCreateHostKey_RejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateHostKey(path); err == nil {
		t.Fatal("expected an error for a corrupt key file")
	}
}
