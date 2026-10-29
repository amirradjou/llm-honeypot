package main

import (
	"flag"

	"github.com/amirradjou/llm-honeypot/internal/geoip"
)

// geoFlags are the optional IP databases behind the country and network
// tables. Lookups are local; no IP is ever sent anywhere.
type geoFlags struct{ country, asn *string }

func addGeoFlags(fs *flag.FlagSet) geoFlags {
	return geoFlags{
		country: fs.String("geoip-country", envOr("HONEYPOT_GEOIP_COUNTRY", ""),
			"country database (.mmdb, DB-IP Lite or GeoLite2) for the source-country table (HONEYPOT_GEOIP_COUNTRY)"),
		asn: fs.String("geoip-asn", envOr("HONEYPOT_GEOIP_ASN", ""),
			"ASN database (.mmdb) for the source-network table (HONEYPOT_GEOIP_ASN)"),
	}
}

// open returns nil, nil when neither database is set.
func (g geoFlags) open() (*geoip.DB, error) {
	if *g.country == "" && *g.asn == "" {
		return nil, nil
	}
	return geoip.Open(*g.country, *g.asn)
}
