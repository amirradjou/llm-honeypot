package analysis

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// locatorFunc adapts a function to Locator.
type locatorFunc func(ip string) (string, string)

func (f locatorFunc) Locate(ip string) (string, string) { return f(ip) }

// testPlaces stands in for the databases: the seeded sessions come from
// 198.51.100.1, .2 and .7 (RFC 5737), and .7 is in neither.
var testPlaces = locatorFunc(func(ip string) (string, string) {
	switch ip {
	case "198.51.100.1":
		return "NL", "AS14061 DigitalOcean, LLC"
	case "198.51.100.2":
		return "CN", "AS4134 Chinanet"
	}
	return "", ""
})

func TestLocateLooksEachIPUpOnce(t *testing.T) {
	sessions := []*Session{{RemoteIP: "198.51.100.1"}, {RemoteIP: "198.51.100.1"}, {RemoteIP: "198.51.100.2"}}
	calls := 0
	Locate(sessions, locatorFunc(func(ip string) (string, string) {
		calls++
		return testPlaces(ip)
	}))
	if calls != 2 {
		t.Fatalf("%d lookups for 2 distinct IPs", calls)
	}
	if s := sessions[1]; s.Country != "NL" || s.Network != "AS14061 DigitalOcean, LLC" {
		t.Fatalf("second session from .1 got %q, %q", s.Country, s.Network)
	}
	Locate(sessions, nil) // no database: nothing changes
	if sessions[2].Country != "CN" {
		t.Fatal("a nil locator cleared the fields")
	}
}

func TestReportShowsCountriesAndNetworks(t *testing.T) {
	sessions, err := Load(seedDashboardData(t))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := WriteReport(&plain, sessions, ReportOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "Source countries") {
		t.Fatal("country table without a database")
	}

	Locate(sessions, testPlaces)
	var buf bytes.Buffer
	if err := WriteReport(&buf, sessions, ReportOptions{Attribution: "IP geolocation by DB-IP."}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Source countries", "NL", "CN", "Source networks", "AS14061 DigitalOcean, LLC"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "_IP geolocation by DB-IP._") {
		t.Errorf("report does not end with the attribution:\n%s", out)
	}
}

func TestDashboardShowsCountriesAndCredit(t *testing.T) {
	d := NewDashboard(seedDashboardData(t), time.Second).WithLocator(testPlaces, "IP geolocation by DB-IP.")
	page := get(t, d, "/").Body.String()
	// The ranked tables are headed by their column name.
	for _, want := range []string{"<th>country</th>", "<th>AS</th>", "AS4134 Chinanet", "198.51.100.1 (NL)", "IP geolocation by DB-IP."} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if md := get(t, d, "/report.md").Body.String(); !strings.Contains(md, "IP geolocation by DB-IP.") {
		t.Error("markdown report lacks the attribution")
	}
}
