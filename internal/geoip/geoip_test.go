package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// writeDB builds a small MaxMind-format database with one record per network.
func writeDB(t *testing.T, dbType string, records map[string]mmdbtype.Map) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		RecordSize:              24,
		IncludeReservedNetworks: true, // the test networks are RFC 5737 documentation ranges
	})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, rec := range records {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.Insert(network, rec); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), dbType+".mmdb")
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

func country(code string) mmdbtype.Map {
	return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}
}

func asn(n uint32, org string) mmdbtype.Map {
	return mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(n),
		"autonomous_system_organization": mmdbtype.String(org),
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	countries := writeDB(t, "DBIP-Country-Lite", map[string]mmdbtype.Map{
		"192.0.2.0/24":    country("NL"),
		"198.51.100.0/24": country("CN"),
	})
	asns := writeDB(t, "DBIP-ASN-Lite", map[string]mmdbtype.Map{
		"192.0.2.0/24": asn(14061, "DigitalOcean, LLC"),
	})
	db, err := Open(countries, asns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLookup(t *testing.T) {
	db := openTestDB(t)
	cases := []struct {
		ip               string
		country, network string
	}{
		{"192.0.2.7", "NL", "AS14061 DigitalOcean, LLC"},
		{"::ffff:192.0.2.7", "NL", "AS14061 DigitalOcean, LLC"}, // IPv4-mapped, as Go sometimes reports it
		{"198.51.100.9", "CN", ""},                              // in the country database only
		{"203.0.113.1", "", ""},                                 // in neither
		{"not-an-ip", "", ""},
	}
	for _, c := range cases {
		gotCountry, gotNetwork := db.Locate(c.ip)
		if gotCountry != c.country || gotNetwork != c.network {
			t.Errorf("Locate(%q) = %q, %q; want %q, %q", c.ip, gotCountry, gotNetwork, c.country, c.network)
		}
	}
}

func TestOpenNeedsADatabase(t *testing.T) {
	if _, err := Open("", ""); err == nil {
		t.Fatal("Open with no paths succeeded")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.mmdb"), ""); err == nil {
		t.Fatal("Open with a missing file succeeded")
	}
}

func TestOneDatabaseIsEnough(t *testing.T) {
	asns := writeDB(t, "GeoLite2-ASN", map[string]mmdbtype.Map{"192.0.2.0/24": asn(64500, "")})
	db, err := Open("", asns)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if c, n := db.Locate("192.0.2.1"); c != "" || n != "AS64500" {
		t.Fatalf("Locate = %q, %q; want \"\", \"AS64500\"", c, n)
	}
	if got := db.Attribution(); !strings.Contains(got, "GeoLite2") || strings.Contains(got, "DB-IP") {
		t.Fatalf("attribution %q", got)
	}
}

func TestAttributionNamesDBIPOnce(t *testing.T) {
	got := openTestDB(t).Attribution()
	if strings.Count(got, "DB-IP") != 1 || !strings.Contains(got, "CC BY 4.0") {
		t.Fatalf("attribution %q", got)
	}
}
