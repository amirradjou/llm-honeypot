package honeypot

import (
	"fmt"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/shell"
)

// Lines end in plain "\n": the terminal turns each into "\r\n", and
// writing "\r\n" here would reach the attacker as "\r\r\n".
//
// loginBanner reproduces the Ubuntu server MOTD an attacker sees right
// after logging in: the header, the system-load block, and the "last
// login" line. It is generated from the machine so the numbers agree with
// uptime, df and free.
func loginBanner(m *machine.Machine, sess *shell.Session) string {
	p := m.Profile
	now := m.Now()
	var b strings.Builder

	fmt.Fprintf(&b, "Welcome to %s (GNU/Linux %s %s)\n\n", p.OSPretty, p.Kernel, p.Arch)
	b.WriteString(" * Documentation:  https://help.ubuntu.com\n")
	b.WriteString(" * Management:     https://landscape.canonical.com\n")
	b.WriteString(" * Support:        https://ubuntu.com/advantage\n\n")

	l1, l5, l15 := m.LoadAvg()
	diskUsed := p.DiskUsedPct
	diskTotalGB := float64(p.DiskGB)
	usedGB := diskTotalGB * float64(diskUsed) / 100
	memUsedPct := 33
	swapUsedPct := 0
	fmt.Fprintf(&b, "  System information as of %s\n\n", now.Format("Mon Jan _2 15:04:05 MST 2006"))
	// landscape-sysinfo pads the left column so the right one lines up.
	left := []string{
		fmt.Sprintf("System load:  %.2f", l1),
		fmt.Sprintf("Usage of /:   %.1f%% of %.2fGB", float64(diskUsed), diskTotalGB),
		fmt.Sprintf("Memory usage: %d%%", memUsedPct),
	}
	right := []string{
		fmt.Sprintf("Processes:             %d", len(p.Processes)+2),
		"Users logged in:       1",
		fmt.Sprintf("IPv4 address for %s: %s", p.Interface, p.IPv4),
	}
	width := 0
	for _, l := range left {
		width = max(width, len(l))
	}
	for i := range left {
		fmt.Fprintf(&b, "  %-*s   %s\n", width, left[i], right[i])
	}
	fmt.Fprintf(&b, "  Swap usage:   %d%%\n\n", swapUsedPct)
	_ = usedGB
	_ = l5
	_ = l15

	updates := int(seedHash(p.Hostname)%40) + 3
	sec := int(seedHash(p.Hostname+"sec")%12) + 1
	fmt.Fprintf(&b, "%d updates can be applied immediately.\n", updates)
	fmt.Fprintf(&b, "%d of these updates are standard security updates.\n", sec)
	b.WriteString("To see these additional updates run: apt list --upgradable\n\n")

	last := now.Add(-52 * time.Hour)
	fmt.Fprintf(&b, "Last login: %s from %s\n", last.Format("Mon Jan _2 15:04:05 2006"), lastLoginIP(p.IPv4))
	return b.String()
}

// lastLoginIP is where the box's admin last logged in from: a host on the
// box's own private network (a bastion or VPN), never the visitor's own
// address, which would read as "you were here two days ago".
func lastLoginIP(boxIP string) string {
	if i := strings.LastIndexByte(boxIP, '.'); i > 0 {
		return boxIP[:i] + ".15"
	}
	return "10.0.0.15"
}

// seedHash is a small stable hash for the banner's fake counters.
func seedHash(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
