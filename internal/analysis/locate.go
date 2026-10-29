package analysis

// Locator maps an IP to an ISO country code and a network such as
// "AS14061 DigitalOcean, LLC", from a local database. internal/geoip
// implements it; nothing here sends an IP anywhere.
type Locator interface {
	Locate(ip string) (country, network string)
}

// Locate fills each session's Country and Network. A nil locator leaves
// them empty, so callers can pass whatever they have.
func Locate(sessions []*Session, loc Locator) {
	if loc == nil {
		return
	}
	type place struct{ country, network string }
	seen := map[string]place{}
	for _, s := range sessions {
		p, ok := seen[s.RemoteIP]
		if !ok {
			p.country, p.network = loc.Locate(s.RemoteIP)
			seen[s.RemoteIP] = p
		}
		s.Country, s.Network = p.country, p.network
	}
}
