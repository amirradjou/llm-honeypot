// Package geoip maps source IPs to a country and a network (ASN) from local
// MaxMind-format databases, DB-IP Lite or GeoLite2. Lookups never leave the
// machine, so a report never sends an attacker's IP to a third party.
package geoip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Info is what the databases know about one IP. Empty fields are unknown.
type Info struct {
	Country string // ISO 3166-1 alpha-2, e.g. "NL"
	ASN     uint
	Org     string // the autonomous system's organisation
}

// Network renders the AS as "AS14061 DigitalOcean, LLC", or "" when unknown.
func (i Info) Network() string {
	switch {
	case i.ASN == 0:
		return ""
	case i.Org == "":
		return fmt.Sprintf("AS%d", i.ASN)
	default:
		return fmt.Sprintf("AS%d %s", i.ASN, i.Org)
	}
}

// DB holds the open databases. Either may be missing.
type DB struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
}

// Open opens a country database, an ASN database, or both; pass "" to skip one.
func Open(countryPath, asnPath string) (*DB, error) {
	if countryPath == "" && asnPath == "" {
		return nil, errors.New("geoip: no database given")
	}
	db := &DB{}
	var err error
	if countryPath != "" {
		if db.country, err = maxminddb.Open(countryPath); err != nil {
			return nil, fmt.Errorf("geoip: country database: %w", err)
		}
	}
	if asnPath != "" {
		if db.asn, err = maxminddb.Open(asnPath); err != nil {
			db.Close()
			return nil, fmt.Errorf("geoip: ASN database: %w", err)
		}
	}
	return db, nil
}

// Close releases the databases.
func (db *DB) Close() error {
	var errs []error
	for _, r := range []*maxminddb.Reader{db.country, db.asn} {
		if r != nil {
			errs = append(errs, r.Close())
		}
	}
	return errors.Join(errs...)
}

// Lookup returns what the databases know about ip. A malformed IP, or one in
// neither database, gives an empty Info.
func (db *DB) Lookup(ip string) Info {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Info{}
	}
	addr = addr.Unmap()
	var info Info
	if db.country != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.country.Lookup(addr).Decode(&rec); err == nil {
			info.Country = rec.Country.ISOCode
		}
	}
	if db.asn != nil {
		var rec struct {
			ASN uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if err := db.asn.Lookup(addr).Decode(&rec); err == nil {
			info.ASN, info.Org = rec.ASN, rec.Org
		}
	}
	return info
}

// Locate is Lookup in the shape the analysis package wants.
func (db *DB) Locate(ip string) (country, network string) {
	info := db.Lookup(ip)
	return info.Country, info.Network()
}

// Attribution is the credit line the databases' licences ask for wherever
// their data is shown: DB-IP Lite is CC BY 4.0, GeoLite2 has its own terms.
func (db *DB) Attribution() string {
	var parts []string
	seen := map[string]bool{}
	for _, r := range []*maxminddb.Reader{db.country, db.asn} {
		if r == nil {
			continue
		}
		var line string
		switch t := r.Metadata.DatabaseType; {
		case strings.HasPrefix(strings.ToLower(t), "dbip"):
			line = "IP geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0."
		case strings.HasPrefix(t, "GeoLite2"):
			line = "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com."
		default:
			line = fmt.Sprintf("IP data: %s.", t)
		}
		if !seen[line] {
			seen[line] = true
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, " ")
}
