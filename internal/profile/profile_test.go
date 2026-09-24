package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_IsValid(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.User("root").UID != 0 {
		t.Fatal("root should be uid 0")
	}
	if p.User("nope") != nil {
		t.Fatal("unknown user should be nil")
	}
	if p.FQDN() != "srv-web01" {
		t.Fatalf("FQDN = %q", p.FQDN())
	}
}

func TestLoad_OverridesOnlyWhatIsListed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, []byte(`{"hostname":"db-02","domain":"corp.local","cpu_cores":8}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Hostname != "db-02" || p.CPUCores != 8 || p.FQDN() != "db-02.corp.local" {
		t.Fatalf("overrides not applied: %+v", p)
	}
	if p.Kernel != Default().Kernel || len(p.Users) != len(Default().Users) {
		t.Fatal("defaults should be kept for unspecified fields")
	}
}

func TestLoad_RejectsIncompleteProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, []byte(`{"users":[{"name":"bob","uid":1000}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a profile without root should be rejected")
	}
}
