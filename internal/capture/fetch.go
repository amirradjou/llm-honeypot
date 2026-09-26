package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Fetcher downloads a payload an attacker referenced.
//
// This is the one part of the project that reaches out to the network, and
// it does so only when an operator explicitly asks. Two consequences are
// unavoidable and worth stating plainly: the bytes it brings back are
// hostile, and the request tells the attacker's server that someone is
// looking. Everything below exists to bound the first problem; the second
// is inherent and is why fetching is opt-in.
type Fetcher struct {
	// MaxBytes caps a download. A payload over the cap is stored truncated
	// and marked as such rather than silently filling the disk.
	MaxBytes int64
	// Timeout bounds one fetch end to end.
	Timeout time.Duration
	// MaxRedirects bounds redirect chains; every hop is re-checked against
	// the address policy.
	MaxRedirects int
	// UserAgent is sent verbatim. It defaults to the wget string the bots
	// themselves use, because servers commonly vary the payload by client
	// and the point is to capture what the attacker would have got.
	UserAgent string
	// AllowPrivate disables the private-address guard. It exists for
	// testing against a local server and should never be set in
	// production: with it on, a URL an attacker chose could make this
	// process reach into the network it runs in.
	AllowPrivate bool

	client *http.Client
}

// Defaults applied to zero fields.
const (
	defaultMaxBytes     = 8 << 20
	defaultTimeout      = 30 * time.Second
	defaultMaxRedirects = 3
	defaultUserAgent    = "Wget/1.21.2"
)

// ErrBlockedAddress is returned when a URL resolves somewhere the fetcher
// refuses to go.
var ErrBlockedAddress = errors.New("capture: refusing to fetch a private or local address")

// ErrUnsupportedScheme is returned for anything but http and https.
var ErrUnsupportedScheme = errors.New("capture: unsupported URL scheme")

// NewFetcher returns a fetcher with defaults filled in.
func NewFetcher(f Fetcher) *Fetcher {
	if f.MaxBytes <= 0 {
		f.MaxBytes = defaultMaxBytes
	}
	if f.Timeout <= 0 {
		f.Timeout = defaultTimeout
	}
	if f.MaxRedirects <= 0 {
		f.MaxRedirects = defaultMaxRedirects
	}
	if f.UserAgent == "" {
		f.UserAgent = defaultUserAgent
	}

	// The address check lives in the dialer's Control hook, which runs
	// after DNS resolution with the concrete address about to be dialled.
	// Checking here rather than on the hostname closes DNS rebinding: a
	// name that resolves to a public address on the first lookup and to
	// 127.0.0.1 on the second is still blocked, because what is actually
	// dialled is what gets inspected.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		if f.AllowPrivate {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return ErrBlockedAddress
		}
		ip := net.ParseIP(host)
		if ip == nil || isBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
		}
		return nil
	}

	f.client = &http.Client{
		Timeout: f.Timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			// A payload server offering compression could otherwise hand
			// back a small response that expands past the cap.
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= f.MaxRedirects {
				return fmt.Errorf("capture: stopped after %d redirects", f.MaxRedirects)
			}
			return checkURL(req.URL)
		},
	}
	return &f
}

// Result is what a fetch produced.
type Result struct {
	Data        []byte
	ContentType string
	Truncated   bool
	Status      int
}

// Fetch downloads rawURL. It never executes anything and never follows a
// redirect to a blocked address.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Result{}, fmt.Errorf("capture: parse %q: %w", rawURL, err)
	}
	if err := checkURL(u); err != nil {
		return Result{}, err
	}
	if !f.AllowPrivate {
		if err := checkHostLiteral(u.Hostname()); err != nil {
			return Result{}, err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := f.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("capture: fetch %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	// Read one byte past the cap so truncation is detectable.
	data, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("capture: read %s: %w", rawURL, err)
	}
	res := Result{ContentType: resp.Header.Get("Content-Type"), Status: resp.StatusCode}
	if int64(len(data)) > f.MaxBytes {
		data = data[:f.MaxBytes]
		res.Truncated = true
	}
	res.Data = data
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("capture: %s returned %s", rawURL, resp.Status)
	}
	return res, nil
}

// checkURL rejects schemes the fetcher will not speak.
func checkURL(u *url.URL) error {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedScheme, u.Scheme)
	}
}

// checkHostLiteral blocks an IP-literal URL early, so the obvious cases
// fail with a clear error instead of a dial error.
func checkHostLiteral(host string) error {
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("%w: localhost", ErrBlockedAddress)
	}
	return nil
}

// isBlockedIP reports whether an address is somewhere this process has no
// business fetching from: its own host, its own network, cloud metadata
// services, or anything not a normal routable address.
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// Carrier-grade NAT, documentation and benchmark ranges, plus the
	// IPv6 unique-local block, none of which should host a payload.
	for _, cidr := range blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var blockedCIDRs = mustCIDRs(
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved
	"fc00::/7",        // IPv6 unique local
)

func mustCIDRs(ss ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ss))
	for _, s := range ss {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("capture: bad CIDR " + s)
		}
		out = append(out, n)
	}
	return out
}
