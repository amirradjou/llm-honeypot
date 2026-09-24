// Package recorder captures everything an attacker does in a session: a
// machine-readable JSONL event log and a human-readable transcript, plus
// extraction of indicators of compromise (URLs, IPs, hashes) from what
// they type.
package recorder

import (
	"regexp"
	"sort"
	"strings"
)

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s"'` + "`" + `<>|]+`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reSHA256 = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	reMD5    = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	reSHA1   = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
)

// IOCs are indicators pulled out of a command line or transcript.
type IOCs struct {
	URLs   []string `json:"urls,omitempty"`
	IPs    []string `json:"ips,omitempty"`
	Hashes []string `json:"hashes,omitempty"`
}

// Empty reports whether nothing was extracted.
func (i IOCs) Empty() bool { return len(i.URLs) == 0 && len(i.IPs) == 0 && len(i.Hashes) == 0 }

// Extract pulls URLs, IPv4 addresses and file hashes from text. IPs that
// appear inside an extracted URL's host are not repeated on their own.
func Extract(text string) IOCs {
	urls := uniq(reURL.FindAllString(text, -1))

	inURL := map[string]bool{}
	for _, u := range urls {
		for _, ip := range reIPv4.FindAllString(u, -1) {
			inURL[ip] = true
		}
	}
	var ips []string
	for _, ip := range uniq(reIPv4.FindAllString(text, -1)) {
		if !inURL[ip] {
			ips = append(ips, ip)
		}
	}

	// Hash detection: longest patterns first so a 64-char string is not
	// also reported as a 40- or 32-char match.
	seen := map[string]bool{}
	var hashes []string
	for _, h := range reSHA256.FindAllString(text, -1) {
		if !seen[h] {
			hashes = append(hashes, h)
			seen[h] = true
		}
	}
	for _, h := range append(reSHA1.FindAllString(text, -1), reMD5.FindAllString(text, -1)...) {
		if !seen[h] && !insideAny(h, hashes) {
			hashes = append(hashes, h)
			seen[h] = true
		}
	}
	sort.Strings(hashes)
	return IOCs{URLs: urls, IPs: ips, Hashes: hashes}
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func insideAny(h string, longer []string) bool {
	for _, l := range longer {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}
