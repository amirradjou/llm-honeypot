package honeypot

import (
	"fmt"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/shell"
)

// loginBanner reproduces the Ubuntu server MOTD an attacker sees right
// after logging in: the header, the system-load block, and the "last
// login" line. It is generated from the machine so the numbers agree with
// uptime, df and free.
func loginBanner(m *machine.Machine, sess *shell.Session) string {
	p := m.Profile
	now := m.Now()
	var b strings.Builder

	fmt.Fprintf(&b, "Welcome to %s (GNU/Linux %s %s)\r\n\r\n", p.OSPretty, p.Kernel, p.Arch)
	b.WriteString(" * Documentation:  https://help.ubuntu.com\r\n")
	b.WriteString(" * Management:     https://landscape.canonical.com\r\n")
	b.WriteString(" * Support:        https://ubuntu.com/advantage\r\n\r\n")

	l1, l5, l15 := m.LoadAvg()
	diskUsed := p.DiskUsedPct
	diskTotalGB := float64(p.DiskGB)
	usedGB := diskTotalGB * float64(diskUsed) / 100
	memUsedPct := 33
	swapUsedPct := 0
	fmt.Fprintf(&b, "  System information as of %s\r\n\r\n", now.Format("Mon Jan  2 15:04:05 PM MST 2006"))
	fmt.Fprintf(&b, "  System load:  %.2f              Processes:             %d\r\n", l1, len(p.Processes)+2)
	fmt.Fprintf(&b, "  Usage of /:   %d%% of %.2fGB    Users logged in:       1\r\n", diskUsed, diskTotalGB)
	fmt.Fprintf(&b, "  Memory usage: %d%%                IPv4 address for %s: %s\r\n", memUsedPct, p.Interface, p.IPv4)
	fmt.Fprintf(&b, "  Swap usage:   %d%%\r\n\r\n", swapUsedPct)
	_ = usedGB
	_ = l5
	_ = l15

	updates := int(seedHash(p.Hostname)%40) + 3
	sec := int(seedHash(p.Hostname+"sec")%12) + 1
	fmt.Fprintf(&b, "%d updates can be applied immediately.\r\n", updates)
	fmt.Fprintf(&b, "%d of these updates are standard security updates.\r\n", sec)
	b.WriteString("To see these additional updates run: apt list --upgradable\r\n\r\n")

	last := now.Add(-52 * time.Hour)
	fmt.Fprintf(&b, "Last login: %s from %s\r\n", last.Format("Mon Jan  2 15:04:05 2006"), lastLoginIP(sess))
	return b.String()
}

func lastLoginIP(sess *shell.Session) string {
	if v := sess.Getenv("SSH_CLIENT"); v != "" {
		return strings.Fields(v)[0]
	}
	return "10.20.30.15"
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
