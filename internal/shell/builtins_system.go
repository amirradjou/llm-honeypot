package shell

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

func (in *Interp) registerSystem() {
	in.Register("uname", cmdUname)
	in.Register("whoami", cmdWhoami)
	in.Register("id", cmdID)
	in.Register("groups", cmdGroups)
	in.Register("hostname", cmdHostname)
	in.Register("hostnamectl", cmdHostnamectl)
	in.Register("uptime", cmdUptime)
	in.Register("w", cmdW)
	in.Register("who", cmdWho)
	in.Register("users", cmdUsers)
	in.Register("last", cmdLast)
	in.Register("ps", cmdPs)
	in.Register("top", cmdTop)
	in.Register("free", cmdFree)
	in.Register("df", cmdDf)
	in.Register("nproc", cmdNproc)
	in.Register("lscpu", cmdLscpu)
	in.Register("lsb_release", cmdLsbRelease)
	in.Register("date", cmdDate)
	in.Register("sleep", cmdSleep)
	in.Register("dmesg", cmdDmesg)
	in.Register("dpkg", cmdDpkg)
	in.Register("dpkg-query", cmdDpkg)
	in.Register("apt", cmdApt)
	in.Register("apt-get", cmdApt)
	in.Register("systemctl", cmdSystemctl)
	in.Register("service", cmdService)
	in.Register("journalctl", cmdJournalctl)
	in.Register("crontab", cmdCrontab)
	in.Register("sudo", cmdSudo)
	in.Register("su", cmdSu)
	in.Register("busybox", cmdBusybox)
	in.Register("sh", cmdShellC)
	in.Register("bash", cmdShellC)
	in.Register("dash", cmdShellC)
	in.Register("printf", cmdPrintf)
	in.Register("seq", cmdSeq)
	in.Register("yes", cmdYes)
	in.Register("lsmod", cmdLsmod)
	in.Register("mount", cmdMount)
}

func cmdUname(c *Context) int {
	p := c.Sess.Machine.Profile
	if len(c.Args) == 1 {
		c.Print("Linux\n")
		return 0
	}
	all := false
	var parts []string
	kernelName, nodeName, kernelRel, kernelVer, machine, os := "Linux", p.Hostname, p.Kernel, p.KernelVersion, p.Arch, "GNU/Linux"
	for _, a := range c.Args[1:] {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		for _, r := range a[1:] {
			switch r {
			case 'a':
				all = true
			case 's':
				parts = append(parts, kernelName)
			case 'n':
				parts = append(parts, nodeName)
			case 'r':
				parts = append(parts, kernelRel)
			case 'v':
				parts = append(parts, kernelVer)
			case 'm', 'p', 'i':
				parts = append(parts, machine)
			case 'o':
				parts = append(parts, os)
			}
		}
	}
	if all {
		c.Printf("%s %s %s %s %s %s\n", kernelName, nodeName, kernelRel, kernelVer, machine, os)
		return 0
	}
	if len(parts) == 0 {
		parts = []string{kernelName}
	}
	c.Print(strings.Join(parts, " ") + "\n")
	return 0
}

func cmdWhoami(c *Context) int {
	c.Print(c.effectiveUser() + "\n")
	return 0
}

func (c *Context) effectiveUser() string {
	if u := c.Sess.Machine.Profile.User(c.Sess.User); u != nil {
		return u.Name
	}
	return c.Sess.User
}

func cmdID(c *Context) int {
	p := c.Sess.Machine.Profile
	name := c.Sess.User
	if len(c.Args) > 1 && !strings.HasPrefix(c.Args[1], "-") {
		name = c.Args[len(c.Args)-1]
	}
	u := p.User(name)
	uid, gid := c.Sess.Cred.UID, c.gid()
	if u != nil {
		uid, gid = u.UID, u.GID
	}
	gname := groupNameFor(c, gid)
	// -u / -g / -n short forms.
	for _, a := range c.Args[1:] {
		switch a {
		case "-u":
			c.Printf("%d\n", uid)
			return 0
		case "-g":
			c.Printf("%d\n", gid)
			return 0
		case "-un", "-nu":
			c.Print(name + "\n")
			return 0
		case "-gn", "-ng":
			c.Print(gname + "\n")
			return 0
		}
	}
	groups := supplementaryGroups(c, name, gid)
	var gb strings.Builder
	for i, g := range groups {
		if i > 0 {
			gb.WriteString(",")
		}
		fmt.Fprintf(&gb, "%d(%s)", g.gid, g.name)
	}
	c.Printf("uid=%d(%s) gid=%d(%s) groups=%s\n", uid, name, gid, gname, gb.String())
	return 0
}

type grp struct {
	gid  int
	name string
}

func supplementaryGroups(c *Context, user string, primaryGID int) []grp {
	out := []grp{{primaryGID, groupNameFor(c, primaryGID)}}
	data, _, err := c.FS().ReadFile("/etc/group")
	if err != nil {
		return out
	}
	seen := map[int]bool{primaryGID: true}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		for _, m := range strings.Split(f[3], ",") {
			if m == user && !seen[gid] {
				out = append(out, grp{gid, f[0]})
				seen[gid] = true
			}
		}
	}
	return out
}

func groupNameFor(c *Context, gid int) string {
	return newIDNames(c).group(gid)
}

func cmdGroups(c *Context) int {
	name := c.Sess.User
	if len(c.Args) > 1 {
		name = c.Args[1]
	}
	gid := c.gid()
	var names []string
	for _, g := range supplementaryGroups(c, name, gid) {
		names = append(names, g.name)
	}
	c.Print(strings.Join(names, " ") + "\n")
	return 0
}

func cmdHostname(c *Context) int {
	p := c.Sess.Machine.Profile
	for _, a := range c.Args[1:] {
		switch a {
		case "-f", "--fqdn":
			c.Print(p.FQDN() + "\n")
			return 0
		case "-i", "-I":
			c.Print(p.IPv4 + " \n")
			return 0
		case "-d":
			c.Print(p.Domain + "\n")
			return 0
		}
	}
	c.Print(p.Hostname + "\n")
	return 0
}

func cmdHostnamectl(c *Context) int {
	p := c.Sess.Machine.Profile
	c.Printf("   Static hostname: %s\n", p.Hostname)
	c.Printf("         Icon name: computer-vm\n")
	c.Printf("           Chassis: vm\n")
	c.Printf("        Machine ID: %s\n", strings.ReplaceAll(machineID(p), "-", ""))
	c.Printf("           Boot ID: %s\n", strings.ReplaceAll(uuidFromShell(p.Hostname+"boot"), "-", ""))
	c.Printf("    Virtualization: kvm\n")
	c.Printf("  Operating System: %s\n", p.OSPretty)
	c.Printf("            Kernel: Linux %s\n", p.Kernel)
	c.Printf("      Architecture: x86-64\n")
	return 0
}

func machineID(p *profile.Profile) string { return uuidFromShell(p.Hostname + "mid") }

func fmtUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%2d:%02d", hours, mins)
	default:
		return fmt.Sprintf("%d min", mins)
	}
}

func cmdUptime(c *Context) int {
	m := c.Sess.Machine
	now := m.Now()
	l1, l5, l15 := m.LoadAvg()
	users := 1
	c.Printf(" %s up %s,  %d user,  load average: %.2f, %.2f, %.2f\n",
		now.Format("15:04:05"), fmtUptime(m.Uptime()), users, l1, l5, l15)
	return 0
}

func cmdW(c *Context) int {
	m := c.Sess.Machine
	now := m.Now()
	l1, l5, l15 := m.LoadAvg()
	c.Printf(" %s up %s,  1 user,  load average: %.2f, %.2f, %.2f\n",
		now.Format("15:04:05"), fmtUptime(m.Uptime()), l1, l5, l15)
	c.Printf("%-8s %-8s %-16s %-8s %-6s %-6s %-6s %s\n", "USER", "TTY", "FROM", "LOGIN@", "IDLE", "JCPU", "PCPU", "WHAT")
	login := now.Add(-14 * time.Minute)
	c.Printf("%-8s %-8s %-16s %-8s %-6s %-6s %-6s %s\n",
		c.Sess.User, "pts/0", clientIP(c), login.Format("15:04"), "2.00s", "0.05s", "0.00s", "-bash")
	return 0
}

func clientIP(c *Context) string {
	if v := c.Sess.Env["SSH_CLIENT"]; v != "" {
		return strings.Fields(v)[0]
	}
	return "10.0.0.100"
}

func cmdWho(c *Context) int {
	now := c.Sess.Machine.Now()
	login := now.Add(-14 * time.Minute)
	c.Printf("%-8s %-8s %s (%s)\n", c.Sess.User, "pts/0", login.Format("2006-01-02 15:04"), clientIP(c))
	return 0
}

func cmdUsers(c *Context) int {
	c.Print(c.Sess.User + "\n")
	return 0
}

func cmdLast(c *Context) int {
	p := c.Sess.Machine.Profile
	now := c.Sess.Machine.Now()
	ip := clientIP(c)
	c.Printf("%-8s %-12s %-16s %s   still logged in\n", c.Sess.User, "pts/0", ip, now.Add(-14*time.Minute).Format("Mon Jan  2 15:04"))
	c.Printf("%-8s %-12s %-16s %s - %s  (%s)\n", "martin", "pts/0", "10.20.30.15",
		now.Add(-52*time.Hour).Format("Mon Jan  2 15:04"), now.Add(-50*time.Hour).Format("15:04"), "2:03")
	c.Printf("%-8s %-12s %-16s %s - %s  (00:41)\n", "deploy", "pts/1", "10.20.30.9",
		now.Add(-74*time.Hour).Format("Mon Jan  2 15:04"), now.Add(-74*time.Hour+41*time.Minute).Format("15:04"))
	c.Printf("reboot   system boot  %-16s %s\n", p.Kernel, c.Sess.Machine.BootTime.Format("Mon Jan  2 15:04"))
	c.Print("\nwtmp begins " + c.Sess.Machine.BootTime.Add(-720*time.Hour).Format("Mon Jan  2 15:04:05 2006") + "\n")
	return 0
}

func cmdPs(c *Context) int {
	p := c.Sess.Machine.Profile
	full := false
	for _, a := range c.Args[1:] {
		if strings.Contains(a, "a") || strings.Contains(a, "e") || strings.Contains(a, "x") || a == "-ef" {
			full = true
		}
	}
	if strings.Contains(strings.Join(c.Args[1:], ""), "ef") {
		c.Printf("%-8s %5s %5s %2s %5s %-8s %-8s %s\n", "UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD")
		for _, pr := range p.Processes {
			c.Printf("%-8s %5d %5d %2d %5s %-8s %-8s %s\n", pr.User, pr.PID, ppidFor(pr.PID), 0, "Aug11", ttyOrQ(pr.TTY), pr.Time, pr.Command)
		}
		c.printShellProcess(true)
		return 0
	}
	// Default aux-style.
	c.Printf("%-8s %5s %4s %4s %7s %6s %-6s %-4s %5s %6s %s\n",
		"USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND")
	list := p.Processes
	if !full {
		// Without a/x, ps shows only this session's processes.
		c.printShellProcess(false)
		return 0
	}
	for _, pr := range list {
		c.Printf("%-8s %5d %4.1f %4.1f %7d %6d %-6s %-4s %5s %6s %s\n",
			pr.User, pr.PID, pr.CPU, pr.Mem, pr.VSZ, pr.RSS, ttyOrQ(pr.TTY), pr.Stat, pr.Start, pr.Time, pr.Command)
	}
	c.printShellProcess(false)
	return 0
}

func (c *Context) printShellProcess(ef bool) {
	pid := c.Sess.PID
	if ef {
		c.Printf("%-8s %5d %5d %2d %5s %-8s %-8s %s\n", c.Sess.User, pid, pid-2, 0, c.Sess.Machine.Now().Add(-14*time.Minute).Format("15:04"), "pts/0", "00:00:00", "-bash")
		c.Printf("%-8s %5d %5d %2d %5s %-8s %-8s %s\n", c.Sess.User, pid+40, pid, 0, c.Sess.Machine.Now().Format("15:04"), "pts/0", "00:00:00", "ps -ef")
		return
	}
	when := c.Sess.Machine.Now().Add(-14 * time.Minute).Format("15:04")
	c.Printf("%-8s %5d %4.1f %4.1f %7d %6d %-6s %-4s %5s %6s %s\n", c.Sess.User, pid, 0.0, 0.1, 9184, 5040, "pts/0", "Ss", when, "0:00", "-bash")
	c.Printf("%-8s %5d %4.1f %4.1f %7d %6d %-6s %-4s %5s %6s %s\n", c.Sess.User, pid+40, 0.0, 0.0, 8892, 3360, "pts/0", "R+", c.Sess.Machine.Now().Format("15:04"), "0:00", "ps aux")
}

func ttyOrQ(t string) string {
	if t == "" {
		return "?"
	}
	return t
}

func ppidFor(pid int) int {
	if pid <= 2 {
		return 0
	}
	if pid < 700 {
		return 1
	}
	return 1
}

func cmdTop(c *Context) int {
	// Non-interactive: print a header snapshot like `top -bn1` and exit.
	m := c.Sess.Machine
	p := m.Profile
	l1, l5, l15 := m.LoadAvg()
	c.Printf("top - %s up %s,  1 user,  load average: %.2f, %.2f, %.2f\n", m.Now().Format("15:04:05"), fmtUptime(m.Uptime()), l1, l5, l15)
	c.Printf("Tasks: %d total,   1 running, %d sleeping,   0 stopped,   0 zombie\n", len(p.Processes)+2, len(p.Processes)+1)
	c.Print("%Cpu(s):  0.7 us,  0.3 sy,  0.0 ni, 98.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st\n")
	total := p.MemMB
	c.Printf("MiB Mem : %8.1f total, %8.1f free, %8.1f used, %8.1f buff/cache\n", float64(total), float64(total)*0.22, float64(total)*0.33, float64(total)*0.45)
	c.Printf("MiB Swap: %8.1f total, %8.1f free, %8.1f used. %8.1f avail Mem\n", float64(p.SwapMB), float64(p.SwapMB), 0.0, float64(total)*0.6)
	c.Print("\n")
	c.Printf("%7s %-8s %3s %3s %8s %7s %7s %-2s %5s %5s %9s %s\n", "PID", "USER", "PR", "NI", "VIRT", "RES", "SHR", "S", "%CPU", "%MEM", "TIME+", "COMMAND")
	shown := p.Processes
	if len(shown) > 15 {
		shown = shown[:15]
	}
	for _, pr := range shown {
		c.Printf("%7d %-8s %3d %3d %8d %7d %7d %-2s %5.1f %5.1f %9s %s\n",
			pr.PID, pr.User, 20, 0, pr.VSZ, pr.RSS, pr.RSS/3, string(pr.Stat[0]), pr.CPU, pr.Mem, pr.Time, procBase(pr.Command))
	}
	return 0
}

func procBase(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return cmd
	}
	base := f[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	return base
}

func cmdFree(c *Context) int {
	p := c.Sess.Machine.Profile
	human := false
	for _, a := range c.Args[1:] {
		if a == "-h" || a == "--human" {
			human = true
		}
	}
	totalKB := p.MemMB * 1024
	usedKB := totalKB * 33 / 100
	freeKB := totalKB * 22 / 100
	buffKB := totalKB * 45 / 100
	availKB := totalKB * 60 / 100
	swapKB := p.SwapMB * 1024
	// Default columns are in mebibytes, which is what `free -m` (the common
	// invocation) shows and is close enough for `free` too.
	val := func(kb int) string {
		if human {
			return humanSize(int64(kb)*1024, true)
		}
		return strconv.Itoa(kb / 1024)
	}
	c.Printf("%15s%12s%12s%12s%12s%12s\n", "total", "used", "free", "shared", "buff/cache", "available")
	c.Printf("Mem:   %12s%12s%12s%12s%12s%12s\n", val(totalKB), val(usedKB), val(freeKB), val(totalKB/50), val(buffKB), val(availKB))
	c.Printf("Swap:  %12s%12s%12s\n", val(swapKB), "0", val(swapKB))
	return 0
}
func cmdDf(c *Context) int {
	p := c.Sess.Machine.Profile
	human := false
	for _, a := range c.Args[1:] {
		if strings.Contains(a, "h") {
			human = true
		}
	}
	totalKB := int64(p.DiskGB) * 1024 * 1024
	usedKB := totalKB * int64(p.DiskUsedPct) / 100
	availKB := totalKB - usedKB
	sz := func(kb int64) string {
		if human {
			return humanSize(kb*1024, true)
		}
		return strconv.FormatInt(kb, 10)
	}
	if human {
		c.Printf("%-20s %5s %5s %5s %5s %s\n", "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on")
	} else {
		c.Printf("%-20s %10s %10s %10s %5s %s\n", "Filesystem", "1K-blocks", "Used", "Available", "Use%", "Mounted on")
	}
	row := func(fs string, kb, used, avail int64, pct int, mnt string) {
		if human {
			c.Printf("%-20s %5s %5s %5s %4d%% %s\n", fs, sz(kb), sz(used), sz(avail), pct, mnt)
		} else {
			c.Printf("%-20s %10s %10s %10s %4d%% %s\n", fs, sz(kb), sz(used), sz(avail), pct, mnt)
		}
	}
	c.printDfPseudo(human)
	row("/dev/sda1", totalKB, usedKB, availKB, p.DiskUsedPct, "/")
	return 0
}

func (c *Context) printDfPseudo(human bool) {
	p := c.Sess.Machine.Profile
	ramKB := int64(p.MemMB) * 1024
	sz := func(kb int64) string {
		if human {
			return humanSize(kb*1024, true)
		}
		return strconv.FormatInt(kb, 10)
	}
	pseudo := []struct {
		fs  string
		kb  int64
		mnt string
	}{
		{"tmpfs", ramKB / 10, "/run"},
		{"tmpfs", ramKB / 2, "/dev/shm"},
		{"tmpfs", 5120, "/run/lock"},
		{"/dev/sda15", 106858, "/boot/efi"},
		{"tmpfs", ramKB / 10, "/run/user/0"},
	}
	for _, x := range pseudo {
		used := x.kb / 50
		if human {
			c.Printf("%-20s %5s %5s %5s %4d%% %s\n", x.fs, sz(x.kb), sz(used), sz(x.kb-used), 2, x.mnt)
		} else {
			c.Printf("%-20s %10s %10s %10s %4d%% %s\n", x.fs, sz(x.kb), sz(used), sz(x.kb-used), 2, x.mnt)
		}
	}
}

func cmdNproc(c *Context) int {
	c.Printf("%d\n", c.Sess.Machine.Profile.CPUCores)
	return 0
}

func cmdLscpu(c *Context) int {
	p := c.Sess.Machine.Profile
	rows := [][2]string{
		{"Architecture", "x86_64"},
		{"  CPU op-mode(s)", "32-bit, 64-bit"},
		{"  Byte Order", "Little Endian"},
		{"CPU(s)", strconv.Itoa(p.CPUCores)},
		{"  On-line CPU(s) list", "0-" + strconv.Itoa(p.CPUCores-1)},
		{"Vendor ID", "GenuineIntel"},
		{"  Model name", p.CPUModel},
		{"    CPU family", "6"},
		{"    Model", "79"},
		{"    Thread(s) per core", "1"},
		{"    Core(s) per socket", strconv.Itoa(p.CPUCores)},
		{"    Socket(s)", "1"},
		{"    Stepping", "1"},
		{"    BogoMIPS", "4788.90"},
		{"Virtualization features", ""},
		{"  Hypervisor vendor", "KVM"},
		{"  Virtualization type", "full"},
		{"Caches (sum of all)", ""},
		{"  L1d", "32 KiB (1 instance)"},
		{"  L1i", "32 KiB (1 instance)"},
		{"  L2", "256 KiB (1 instance)"},
		{"  L3", "35 MiB (1 instance)"},
	}
	for _, r := range rows {
		if r[1] == "" {
			c.Printf("%s:\n", r[0])
		} else {
			c.Printf("%-40s%s\n", r[0]+":", r[1])
		}
	}
	return 0
}

func cmdLsbRelease(c *Context) int {
	p := c.Sess.Machine.Profile
	short := false
	for _, a := range c.Args[1:] {
		if a == "-s" {
			short = true
		}
	}
	get := func(label, val string) {
		if short {
			c.Print(val + "\n")
		} else {
			c.Printf("%s:\t%s\n", label, val)
		}
	}
	printed := false
	for _, a := range c.Args[1:] {
		switch a {
		case "-i":
			get("Distributor ID", p.OSName)
			printed = true
		case "-d":
			get("Description", p.OSPretty)
			printed = true
		case "-r":
			get("Release", strings.Fields(p.OSVersion)[0])
			printed = true
		case "-c":
			get("Codename", p.OSCodename)
			printed = true
		case "-a":
			c.Printf("Distributor ID:\t%s\nDescription:\t%s\nRelease:\t%s\nCodename:\t%s\n", p.OSName, p.OSPretty, strings.Fields(p.OSVersion)[0], p.OSCodename)
			printed = true
		}
	}
	if !printed {
		c.Print("No LSB modules are available.\n")
	}
	return 0
}

func cmdDate(c *Context) int {
	now := c.Sess.Machine.Now()
	for i := 1; i < len(c.Args); i++ {
		a := c.Args[i]
		if strings.HasPrefix(a, "+") {
			c.Print(strftime(a[1:], now) + "\n")
			return 0
		}
		if a == "-u" {
			now = now.UTC()
		}
		if a == "+%s" {
			c.Printf("%d\n", now.Unix())
			return 0
		}
	}
	c.Print(now.Format("Mon Jan  2 15:04:05 MST 2006") + "\n")
	return 0
}

// strftime handles the handful of %-codes scripts actually use.
func strftime(f string, t time.Time) string {
	rep := strings.NewReplacer(
		"%Y", t.Format("2006"), "%m", t.Format("01"), "%d", t.Format("02"),
		"%H", t.Format("15"), "%M", t.Format("04"), "%S", t.Format("05"),
		"%F", t.Format("2006-01-02"), "%T", t.Format("15:04:05"),
		"%s", strconv.FormatInt(t.Unix(), 10), "%y", t.Format("06"),
		"%b", t.Format("Jan"), "%a", t.Format("Mon"), "%j", fmt.Sprintf("%03d", t.YearDay()),
		"%%", "%",
	)
	return rep.Replace(f)
}

func cmdSleep(c *Context) int {
	// Sleeps are capped hard so a bot cannot pin the honeypot with sleep 9999.
	const cap = 3 * time.Second
	total := time.Duration(0)
	for _, a := range c.Args[1:] {
		total += parseSleep(a)
	}
	if total > cap {
		total = cap
	}
	time.Sleep(total)
	return 0
}

func parseSleep(s string) time.Duration {
	mult := time.Second
	switch {
	case strings.HasSuffix(s, "m"):
		mult, s = time.Minute, strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "h"):
		mult, s = time.Hour, strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "d"):
		mult, s = 24*time.Hour, strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "s"):
		s = strings.TrimSuffix(s, "s")
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return time.Duration(f * float64(mult))
}

func cmdDmesg(c *Context) int {
	// Read the seeded kern.log if present; otherwise a short canned boot log.
	if data, err := c.readTarget("/var/log/kern.log"); err == nil && len(data) > 0 {
		c.Stdout.Write(data)
		return 0
	}
	c.Errorf("read kernel buffer failed: Operation not permitted")
	return 1
}

func cmdLsmod(c *Context) int {
	data, err := c.readTarget("/proc/modules")
	if err != nil {
		return 1
	}
	c.Print("Module                  Size  Used by\n")
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 {
			c.Printf("%-22s %6s  %s\n", f[0], f[1], f[2])
		}
	}
	return 0
}

func cmdMount(c *Context) int {
	c.Print("sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n")
	c.Print("proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n")
	c.Print("udev on /dev type devtmpfs (rw,nosuid,relatime,size=1973016k,nr_inodes=493254,mode=755,inode64)\n")
	c.Print("/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n")
	c.Print("tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=403016k,mode=755,inode64)\n")
	c.Print("/dev/sda15 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro)\n")
	return 0
}

func cmdDpkg(c *Context) int {
	p := c.Sess.Machine.Profile
	for _, a := range c.Args[1:] {
		if a == "-l" || a == "--list" {
			c.Print("Desired=Unknown/Install/Remove/Purge/Hold\n")
			c.Print("| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n")
			c.Print("|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n")
			c.Printf("||/ %-30s %-24s %-12s %s\n", "Name", "Version", "Architecture", "Description")
			c.Print("+++-==============================-========================-============-=================================\n")
			pkgs := append([]string(nil), p.Packages...)
			sort.Strings(pkgs)
			for _, pk := range pkgs {
				c.Printf("ii  %-30s %-24s %-12s %s\n", pk, fakeVersion(pk), "amd64", pk+" package")
			}
			return 0
		}
	}
	return 0
}

func fakeVersion(pkg string) string {
	h := seedInode(pkg)
	return fmt.Sprintf("%d.%d.%d-%dubuntu%d", h%4+1, h%10, h%20, h%5, h%3+1)
}

func cmdApt(c *Context) int {
	if len(c.Args) < 2 {
		c.Print("apt 2.4.13 (amd64)\n")
		return 0
	}
	switch c.Args[1] {
	case "update":
		c.Print("Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n")
		c.Print("Hit:2 http://security.ubuntu.com/ubuntu jammy-security InRelease\n")
		c.Print("Hit:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n")
		c.Print("Reading package lists... Done\n")
		if !c.Sess.Cred.IsRoot() {
			c.Print("Reading package lists... Done\nW: ... Permission denied\n")
		}
		return 0
	case "install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade":
		if !c.Sess.Cred.IsRoot() {
			c.Print("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n")
			c.Print("E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n")
			return 100
		}
		c.Print("Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n")
		if c.Args[1] == "install" && len(c.Args) > 2 {
			c.Printf("E: Unable to locate package %s\n", c.Args[2])
			return 100
		}
		c.Print("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
		return 0
	}
	return 0
}

func cmdSystemctl(c *Context) int {
	if len(c.Args) < 2 {
		return 0
	}
	switch c.Args[1] {
	case "status":
		unit := "the system"
		if len(c.Args) > 2 {
			unit = c.Args[2]
		}
		c.Printf("● %s - service\n     Loaded: loaded\n     Active: active (running)\n", unit)
		return 0
	case "is-active":
		c.Print("active\n")
		return 0
	case "is-enabled":
		c.Print("enabled\n")
		return 0
	case "start", "stop", "restart", "reload", "enable", "disable":
		if !c.Sess.Cred.IsRoot() {
			unit := ""
			if len(c.Args) > 2 {
				unit = c.Args[2]
			}
			c.Printf("Failed to %s %s: Access denied\n", c.Args[1], unit)
			c.Print("See system logs and 'systemctl status' for details.\n")
			return 1
		}
		return 0
	case "list-units", "list-unit-files":
		c.Print("UNIT FILE                                  STATE           VENDOR PRESET\n")
		c.Print("ssh.service                                enabled         enabled\n")
		c.Print("nginx.service                              enabled         enabled\n")
		c.Print("postgresql.service                         enabled         enabled\n")
		c.Print("bakery.service                             enabled         enabled\n")
		return 0
	}
	return 0
}

func cmdService(c *Context) int {
	if len(c.Args) >= 3 {
		switch c.Args[2] {
		case "status":
			c.Printf("● %s.service - service\n     Active: active (running)\n", c.Args[1])
		}
	}
	return 0
}

func cmdJournalctl(c *Context) int {
	if data, err := c.readTarget("/var/log/syslog"); err == nil && len(data) > 0 {
		c.Stdout.Write(data)
		return 0
	}
	c.Print("-- No entries --\n")
	return 0
}

func cmdCrontab(c *Context) int {
	user := c.Sess.User
	var op, file string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-u" && i+1 < len(args):
			user = args[i+1]
			i++
		case a == "-l" || a == "-r" || a == "-e" || a == "-i":
			op = a
		case a == "-":
			file = "-"
		case strings.HasPrefix(a, "-"):
		default:
			file = a
		}
	}
	spool := "/var/spool/cron/crontabs/" + user
	switch op {
	case "-l":
		data, err := c.readTarget(spool)
		if err != nil || len(data) == 0 {
			fmt.Fprintf(c.Stderr, "no crontab for %s\n", user)
			return 1
		}
		c.Stdout.Write(stripCronHeader(data))
		return 0
	case "-r", "-ir":
		if _, err := c.FS().Stat(spool); err != nil {
			fmt.Fprintf(c.Stderr, "no crontab for %s\n", user)
			return 1
		}
		_ = c.FS().Remove(spool)
		return 0
	case "-e":
		return 0
	}
	var data []byte
	if file == "" || file == "-" {
		data, _ = io.ReadAll(c.Stdin)
		file = "-"
	} else {
		d, err := c.readTarget(file)
		if err != nil {
			fmt.Fprintf(c.Stderr, "%s: No such file or directory\n", file)
			return 1
		}
		data = d
	}
	// Installing a crontab is a classic persistence step; it only ever
	// lands in the session's own filesystem.
	header := fmt.Sprintf("# DO NOT EDIT THIS FILE - edit the master and reinstall.\n# (%s installed on %s)\n# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)\n",
		file, c.Sess.Machine.Now().Format("Mon Jan _2 15:04:05 2006"))
	gid := 0
	for id, name := range newIDNames(c).groups {
		if name == "crontab" {
			gid = id
		}
	}
	opts := vfs.WriteOptions{Mode: 0o600, UID: c.Sess.Cred.UID, GID: gid}
	if err := c.FS().WriteFile(spool, append([]byte(header), data...), opts); err != nil {
		fmt.Fprintf(c.Stderr, "crontab: installing new crontab: %s\n", vfs.Strerror(err))
		return 1
	}
	return 0
}

// stripCronHeader drops the "DO NOT EDIT" banner Debian's crontab writes,
// which `crontab -l` does not show.
func stripCronHeader(data []byte) []byte {
	s := string(data)
	if !strings.HasPrefix(s, "# DO NOT EDIT THIS FILE") {
		return data
	}
	for k := 0; k < 3; k++ {
		if i := strings.IndexByte(s, '\n'); i >= 0 && strings.HasPrefix(s, "#") {
			s = s[i+1:]
		}
	}
	return []byte(s)
}

func cmdSudo(c *Context) int {
	// Strip sudo [-options] and any VAR=val, then run the rest as the target
	// user (root by default, or whoever -u names).
	rest := c.Args[1:]
	targetUser := "root"
	for len(rest) > 0 {
		a := rest[0]
		switch {
		case a == "-i" || a == "-s":
			c.Sess.elevated = true
			rest = rest[1:]
			if len(rest) == 0 {
				return 0
			}
		case a == "-u" && len(rest) > 1:
			targetUser = rest[1]
			rest = rest[2:]
		case strings.HasPrefix(a, "-"):
			rest = rest[1:]
		case isAssignment(a):
			rest = rest[1:]
		default:
			goto run
		}
	}
run:
	if len(rest) == 0 {
		return 0
	}
	saved := c.Sess.Cred
	savedUser := c.Sess.User
	if tu := c.Sess.Machine.Profile.User(targetUser); tu != nil {
		c.Sess.Cred = vfsCred(tu.UID, tu.GID)
		c.Sess.User = tu.Name
	} else {
		c.Sess.Cred = vfsRoot()
		c.Sess.User = targetUser
	}
	line := shellQuoteJoin(rest)
	status := c.Interp.run(c.Sess, line, c.Stdin, c.Stdout, c.Stderr)
	c.Sess.Cred = saved
	c.Sess.User = savedUser
	return status
}

func cmdSu(c *Context) int {
	// su [-] [user] [-c cmd]; we accept and, for a bare `su`, note elevation.
	target := "root"
	var cmd string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-" || args[i] == "-l" || args[i] == "--login":
		case args[i] == "-c" && i+1 < len(args):
			cmd = args[i+1]
			i++
		case !strings.HasPrefix(args[i], "-"):
			target = args[i]
		}
	}
	tu := c.Sess.Machine.Profile.User(target)
	saved := c.Sess.Cred
	savedUser := c.Sess.User
	if tu != nil {
		c.Sess.Cred = vfsCred(tu.UID, tu.GID)
		c.Sess.User = tu.Name
	} else {
		c.Sess.Cred = vfsRoot()
		c.Sess.User = target
	}
	if cmd != "" {
		status := c.Interp.run(c.Sess, cmd, c.Stdin, c.Stdout, c.Stderr)
		c.Sess.Cred = saved
		c.Sess.User = savedUser
		return status
	}
	// `su` with no -c would open a subshell; we simply switch the session
	// user for subsequent commands, which is what the attacker wanted.
	return 0
}

func cmdBusybox(c *Context) int {
	if len(c.Args) < 2 {
		c.Print("BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.\nBusyBox is copyrighted by many authors between 1998-2015.\nLicensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\nUsage: busybox [function [arguments]...]\n   or: busybox --list[-full]\n   or: busybox --install [-s] [DIR]\n   or: function [arguments]...\n")
		return 0
	}
	applet := c.Args[1]
	// Mirai and friends probe with `busybox ECCHI`, `busybox MIRAI`, etc.
	if strings.ToUpper(applet) == applet && !c.Interp.Has(strings.ToLower(applet)) {
		fmt.Fprintf(c.Stderr, "%s: applet not found\n", applet)
		return 127
	}
	if c.Interp.Has(applet) {
		sub := append([]string{applet}, c.Args[2:]...)
		nctx := *c
		nctx.Args = sub
		return c.Interp.cmds[applet](&nctx)
	}
	fmt.Fprintf(c.Stderr, "%s: applet not found\n", applet)
	return 127
}

// cmdShellC handles `sh -c "..."` / `bash -c "..."`; without -c it accepts
// a script file argument or does nothing (a nested interactive shell just
// returns to the same session).
func cmdShellC(c *Context) int {
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" && i+1 < len(args):
			return c.Interp.run(c.Sess, args[i+1], c.Stdin, c.Stdout, c.Stderr)
		case strings.HasPrefix(a, "-"):
			// -x, -e, etc.: ignore
		default:
			// Treat as a script path: read and run each line.
			data, err := c.readTarget(a)
			if err != nil {
				c.Errorf("%s: %s", a, "No such file or directory")
				return 127
			}
			status := 0
			for _, line := range strings.Split(string(data), "\n") {
				if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				status = c.Interp.run(c.Sess, line, c.Stdin, c.Stdout, c.Stderr)
			}
			return status
		}
	}
	return 0
}

func cmdPrintf(c *Context) int {
	args := c.Args[1:]
	varName := ""
	if len(args) >= 2 && args[0] == "-v" {
		varName, args = args[1], args[2:]
	}
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprint(c.Stderr, "-bash: printf: usage: printf [-v var] format [arguments]\n")
		return 2
	}
	out, status := bashPrintf(c, expandEscapes(args[0]), args[1:])
	if varName != "" {
		c.Sess.Env[varName] = out
		return status
	}
	c.Print(out)
	return status
}

// bashPrintf formats like bash's printf builtin: the format is reused until
// every argument is consumed, missing arguments read as "" or 0, and %b
// expands backslash escapes in its argument.
func bashPrintf(c *Context, format string, args []string) (string, int) {
	var b strings.Builder
	status := 0
	ai := 0
	next := func() (string, bool) {
		if ai < len(args) {
			ai++
			return args[ai-1], true
		}
		return "", false
	}
	num := func(s string) int64 {
		if s == "" {
			return 0
		}
		if len(s) > 1 && (s[0] == '\'' || s[0] == '"') {
			return int64([]rune(s[1:])[0])
		}
		n, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			fmt.Fprintf(c.Stderr, "-bash: printf: %s: invalid number\n", s)
			status = 1
		}
		return n
	}
	for pass := 0; pass < 10000; pass++ {
		consumed := ai
		for i := 0; i < len(format); i++ {
			if format[i] != '%' || i+1 >= len(format) {
				b.WriteByte(format[i])
				continue
			}
			j := i + 1
			for j < len(format) && strings.IndexByte("-+ #0", format[j]) >= 0 {
				j++
			}
			spec := format[i:j]
			for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '.' || format[j] == '*') {
				if format[j] == '*' {
					v, _ := next()
					spec += strconv.FormatInt(num(v), 10)
				} else {
					spec += string(format[j])
				}
				j++
			}
			if j >= len(format) {
				b.WriteString(format[i:])
				break
			}
			verb := format[j]
			i = j
			switch verb {
			case '%':
				b.WriteByte('%')
			case 's':
				v, _ := next()
				fmt.Fprintf(&b, spec+"s", v)
			case 'b':
				v, _ := next()
				fmt.Fprintf(&b, spec+"s", expandEscapes(v))
			case 'q':
				v, _ := next()
				b.WriteString(shellQuoteJoin([]string{v}))
			case 'c':
				if v, _ := next(); v != "" {
					fmt.Fprintf(&b, spec+"c", []rune(v)[0])
				}
			case 'd', 'i':
				v, _ := next()
				fmt.Fprintf(&b, spec+"d", num(v))
			case 'u':
				v, _ := next()
				fmt.Fprintf(&b, spec+"d", uint64(num(v)))
			case 'o', 'x', 'X':
				v, _ := next()
				fmt.Fprintf(&b, spec+string(verb), num(v))
			case 'f', 'F', 'e', 'E', 'g', 'G':
				v, _ := next()
				f, err := strconv.ParseFloat(v, 64)
				if err != nil && v != "" {
					fmt.Fprintf(c.Stderr, "-bash: printf: %s: invalid number\n", v)
					status = 1
				}
				fmt.Fprintf(&b, spec+string(verb), f)
			default:
				fmt.Fprintf(c.Stderr, "-bash: printf: `%c': invalid format character\n", verb)
				return b.String(), 1
			}
		}
		if ai >= len(args) || ai == consumed || b.Len() > 1<<20 {
			break
		}
	}
	return b.String(), status
}

func cmdSeq(c *Context) int {
	nums := c.Args[1:]
	var start, step, end int
	start, step = 1, 1
	switch len(nums) {
	case 1:
		end, _ = strconv.Atoi(nums[0])
	case 2:
		start, _ = strconv.Atoi(nums[0])
		end, _ = strconv.Atoi(nums[1])
	case 3:
		start, _ = strconv.Atoi(nums[0])
		step, _ = strconv.Atoi(nums[1])
		end, _ = strconv.Atoi(nums[2])
	default:
		return 1
	}
	if step == 0 {
		return 1
	}
	count := 0
	for i := start; (step > 0 && i <= end) || (step < 0 && i >= end); i += step {
		c.Printf("%d\n", i)
		count++
		if count > 100000 {
			break
		}
	}
	return 0
}

func cmdYes(c *Context) int {
	// `yes` normally loops forever; a honeypot must not. Print a bounded
	// burst and stop, which is enough to answer `yes | command` prompts.
	msg := "y"
	if len(c.Args) > 1 {
		msg = strings.Join(c.Args[1:], " ")
	}
	for i := 0; i < 1000; i++ {
		c.Print(msg + "\n")
	}
	return 0
}
