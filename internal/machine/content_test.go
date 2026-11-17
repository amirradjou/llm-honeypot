package machine

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// Every file reads back exactly the size ls reports, model or no model: a
// placeholder serves its built-in content until a model replaces it.
func TestSeed_EveryFileServesItsSize(t *testing.T) {
	m := testMachine(t)
	var placeholders int
	err := m.FS.Walk("/", func(p string, info vfs.Info) error {
		if info.IsDir() || info.IsSymlink() || info.IsDevice() || strings.HasPrefix(p, "/proc") {
			return nil
		}
		data, rinfo, err := m.FS.ReadFile(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			return nil
		}
		if rinfo.Placeholder {
			placeholders++
		}
		// opaque binaries cap a single read; everything else is exact
		if want := min(info.Size, vfs.MaxOpaqueRead); int64(len(data)) != want {
			t.Errorf("%s: ls says %d bytes, a read gives %d", p, info.Size, len(data))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if placeholders == 0 {
		t.Error("expected a few model-fillable placeholders to remain")
	}
}

// The files bots read most have real content.
func TestSeed_FilesBotsReadAreNotEmpty(t *testing.T) {
	m := testMachine(t)
	for _, p := range []string{"/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log", "/var/log/nginx/access.log",
		"/var/log/nginx/error.log", "/var/lib/dpkg/status", "/etc/services", "/etc/ssh/ssh_config", "/etc/protocols",
		"/etc/nginx/mime.types", "/var/log/dpkg.log", "/proc/net/tcp", "/proc/net/route", "/proc/stat"} {
		data, _, err := m.FS.ReadFile(p)
		if err != nil || len(data) < 100 {
			t.Errorf("%s: %d bytes, %v", p, len(data), err)
		}
	}
	// auth.log belongs to syslog:adm, as on Ubuntu.
	info, _ := m.FS.Stat("/var/log/auth.log")
	if u := m.Profile.User("syslog"); u == nil || info.UID != u.UID || info.GID != 4 {
		t.Errorf("auth.log owner %d:%d", info.UID, info.GID)
	}
}

// auth.log's accepted logins are exactly the logins `last` reports.
func TestLogs_AuthLogMatchesLoginHistory(t *testing.T) {
	m := testMachine(t)
	data, _, _ := m.FS.ReadFile("/var/log/auth.log")
	var accepted []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "Accepted publickey for ") {
			accepted = append(accepted, line)
		}
	}
	now := m.Now().Truncate(time.Minute)
	logins := m.Logins(weekStart(now), now)
	if len(logins) == 0 {
		t.Fatal("no logins this week; pick another test clock")
	}
	if len(accepted) != len(logins) {
		t.Fatalf("auth.log has %d accepted logins, history has %d", len(accepted), len(logins))
	}
	for i, l := range logins {
		want := fmt.Sprintf("%s %s sshd[%d]: Accepted publickey for %s from %s port %d", l.Start.Format(time.Stamp), m.Profile.Hostname, l.PID, l.User, l.From, l.Port)
		if !strings.HasPrefix(accepted[i], want) {
			t.Errorf("login %d:\n got %s\nwant %s", i, accepted[i], want)
		}
	}
	if !strings.Contains(string(data), "Failed password for root from ") || !strings.Contains(string(data), "Invalid user ") {
		t.Error("auth.log should show the usual password guessing")
	}
}

// Logs are a function of the clock: the same minute gives the same bytes,
// and a later minute in the same week only appends.
func TestLogs_DeterministicAndAppendOnly(t *testing.T) {
	m := testMachine(t)
	now := m.Now().Truncate(time.Minute)
	a1, _ := m.authLog(now)
	a2, _ := m.authLog(now)
	if string(a1) != string(a2) {
		t.Fatal("auth.log differs for the same clock")
	}
	later, _ := m.authLog(now.Add(3 * time.Hour))
	if !strings.HasPrefix(string(later), string(a1)) || len(later) <= len(a1) {
		t.Errorf("auth.log three hours later is not an extension (%d -> %d bytes)", len(a1), len(later))
	}
	m2 := testMachine(t)
	b, _, _ := m2.FS.ReadFile("/var/log/syslog")
	c, _, _ := m.FS.ReadFile("/var/log/syslog")
	if string(b) != string(c) {
		t.Error("two machines on the same clock wrote different syslogs")
	}
}

// New sessions see logs up to their own start, not the seed time.
func TestNewSessionFS_RefreshesLogs(t *testing.T) {
	clock := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m, err := New(profile.Default(), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	before, _, _ := m.NewSessionFS().ReadFile("/var/log/kern.log")
	clock = clock.Add(5 * time.Hour)
	fsys := m.NewSessionFS()
	after, info, _ := fsys.ReadFile("/var/log/kern.log")
	if len(after) <= len(before) {
		t.Errorf("kern.log did not grow: %d -> %d bytes", len(before), len(after))
	}
	if info.ModTime.Before(clock.Add(-30 * time.Minute)) {
		t.Errorf("kern.log mtime %v is stale at %v", info.ModTime, clock)
	}
}

// Logs name only the box and documentation addresses (RFC 5737), never
// anything about the host the honeypot runs on.
func TestLogs_OnlyDocumentationAddresses(t *testing.T) {
	m := testMachine(t)
	p := m.Profile
	// not after a "/": "Chrome/129.0.0.0" is a version
	ipRE := regexp.MustCompile(`(?:^|[^/\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	allowed := map[string]bool{p.IPv4: true, p.Gateway: true, "127.0.0.1": true, "0.0.0.0": true}
	for _, l := range m.logFiles() {
		data, _, _ := m.FS.ReadFile(l.path)
		for _, mt := range ipRE.FindAllStringSubmatch(string(data), -1) {
			ip := mt[1]
			if allowed[ip] || strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.") {
				continue
			}
			if l.path == "/var/log/dpkg.log" || l.path == "/var/log/postgresql/postgresql-14-main.log" {
				continue // package versions and timestamps look like addresses
			}
			t.Errorf("%s names %s", l.path, ip)
			break
		}
	}
}

// One package list feeds dpkg -l, dpkg -s and /var/lib/dpkg/status, and it
// holds everything the profile says the admin installed.
func TestPackages_OneListEverywhere(t *testing.T) {
	m := testMachine(t)
	pkgs := m.Packages()
	if len(pkgs) < 400 {
		t.Fatalf("only %d packages; a 22.04 server has several hundred", len(pkgs))
	}
	status, _, _ := m.FS.ReadFile("/var/lib/dpkg/status")
	for _, p := range pkgs {
		st := m.PackageStatus(p.Name)
		if !strings.Contains(st, "\nVersion: "+p.Version+"\n") {
			t.Errorf("%s: dpkg -l says %s, status says %q", p.Name, p.Version, st)
		}
		if !strings.Contains(string(status), "Package: "+p.Name+"\n") {
			t.Errorf("%s missing from /var/lib/dpkg/status", p.Name)
		}
	}
	for _, name := range m.Profile.Packages {
		if _, ok := m.Package(name); !ok {
			t.Errorf("profile package %s is not installed", name)
		}
	}
	for _, name := range []string{"gcc", "nmap", "docker.io", "kubectl", "mysql-client", "redis-tools", "emacs", "ruby"} {
		if _, ok := m.Package(name); ok {
			t.Errorf("%s should not be on a small web VPS", name)
		}
	}
	for _, bin := range []string{"/usr/bin/gcc", "/usr/bin/nmap", "/usr/bin/docker", "/usr/bin/kubectl", "/usr/bin/mysql", "/usr/bin/redis-cli", "/usr/bin/ruby", "/usr/bin/emacs"} {
		if m.FS.Exists(bin) {
			t.Errorf("%s exists but no installed package provides it", bin)
		}
	}
}

// The profile describes the recorded box: kernel, sshd banner, release.
func TestProfileMatchesRecordedBox(t *testing.T) {
	p := profile.Default()
	if got := refString("kernel-release"); p.Kernel != got {
		t.Errorf("profile kernel %s, recorded %s", p.Kernel, got)
	}
	if got := refString("kernel-version"); p.KernelVersion != got {
		t.Errorf("profile kernel version %q, recorded %q", p.KernelVersion, got)
	}
	ssh := refString("openssh-version") // 1:8.9p1-3ubuntu0.18
	_, upstream, _ := strings.Cut(ssh, ":")
	ver, deb, _ := strings.Cut(upstream, "-")
	if want := "SSH-2.0-OpenSSH_" + ver + " Ubuntu-" + deb; p.SSHVersion != want {
		t.Errorf("profile banner %q, recorded openssh-server %s wants %q", p.SSHVersion, ssh, want)
	}
	if got := refString("os-version"); !strings.HasPrefix(got, strings.TrimSuffix(p.OSVersion, " LTS")) {
		t.Errorf("profile release %s, recorded %s", p.OSVersion, got)
	}
}

// dpkg.log's upgrades end at the versions dpkg -l shows.
func TestLogs_DpkgLogUpgradesToInstalledVersions(t *testing.T) {
	m := testMachine(t)
	for _, g := range upgradeGroups {
		for _, name := range g {
			p, ok := m.Package(name)
			if !ok {
				t.Errorf("upgrade group package %s is not installed", name)
				continue
			}
			if _, ok := previousVersion(p.Version); !ok {
				t.Errorf("%s %s has no previous version", name, p.Version)
			}
		}
	}
	end := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	data, _ := m.dpkgLog(end)
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 6 && f[2] == "upgrade" {
			n++
			name, _, _ := strings.Cut(f[3], ":")
			if p, _ := m.Package(name); f[5] != p.Version {
				t.Errorf("dpkg.log upgrades %s to %s, dpkg -l has %s", name, f[5], p.Version)
			}
		}
	}
	if n == 0 {
		t.Error("no unattended upgrades in four weeks")
	}
}

func TestPreviousVersion(t *testing.T) {
	for in, want := range map[string]string{
		"1.9.9-1ubuntu2.7":        "1.9.9-1ubuntu2.6",
		"1:8.9p1-3ubuntu0.18":     "1:8.9p1-3ubuntu0.17",
		"3.10.12-1~22.04.18":      "3.10.12-1~22.04.17",
		"2.9.13+dfsg-1ubuntu0.14": "2.9.13+dfsg-1ubuntu0.13",
	} {
		if got, ok := previousVersion(in); !ok || got != want {
			t.Errorf("previousVersion(%s) = %s, want %s", in, got, want)
		}
	}
	if _, ok := previousVersion("1.0-0"); ok {
		t.Error("cannot go below 0")
	}
}

// /usr/bin keeps the recorded modes: setuid sudo, setgid crontab.
func TestBins_RecordedModes(t *testing.T) {
	m := testMachine(t)
	sudo, _ := m.FS.Stat("/usr/bin/sudo")
	if sudo.Mode&fs.ModeSetuid == 0 || sudo.Mode.Perm() != 0o755 {
		t.Errorf("sudo mode %v", sudo.Mode)
	}
	cron, _ := m.FS.Stat("/usr/bin/crontab")
	if cron.Mode&fs.ModeSetgid == 0 || cron.GID != binGroups["crontab"] {
		t.Errorf("crontab mode %v gid %d", cron.Mode, cron.GID)
	}
	if target, err := m.FS.RealPath("/usr/bin/vi"); err != nil || target != "/usr/bin/vim.basic" {
		t.Errorf("vi -> %s, %v", target, err)
	}
}
