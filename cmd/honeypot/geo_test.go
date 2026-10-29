package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// writeCountryDB writes a DB-IP-style country database that puts the RFC 5737
// test range 198.51.100.0/24 in the Netherlands.
func writeCountryDB(t *testing.T, dir string) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "DBIP-Country-Lite", RecordSize: 24, IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR("198.51.100.0/24")
	if err := tree.Insert(network, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("NL")}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "country.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReportCommandWithCountryDatabase(t *testing.T) {
	dir := t.TempDir()
	seedRecording(t, dir)
	out := filepath.Join(dir, "report.md")
	if err := runReport([]string{"-data", dir, "-o", out, "-geoip-country", writeCountryDB(t, t.TempDir())}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Source countries", "| `NL` | 1 |", "DB-IP", "CC BY 4.0"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("report missing %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "Source networks") {
		t.Error("network table without an ASN database")
	}
}

func TestGeoFlagsRejectAMissingDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.mmdb")
	if err := runReport([]string{"-data", t.TempDir(), "-geoip-asn", missing}); err == nil {
		t.Fatal("report accepted a missing ASN database")
	}
	if err := runDashboard([]string{"-geoip-country", missing}); err == nil {
		t.Fatal("dashboard accepted a missing country database")
	}
}
