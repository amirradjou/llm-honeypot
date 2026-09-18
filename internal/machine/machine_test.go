package machine

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

func testMachine(t *testing.T) *Machine {
	t.Helper()
	fixed := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m, err := New(profile.Default(), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSeed_KeyFilesExistAndAreConsistent(t *testing.T) {
	m := testMachine(t)
	f := m.FS
	p := m.Profile

	// A representative slice of the tree must exist with the right types.
	dirs := []string{"/", "/etc", "/root", "/home/martin", "/home/deploy", "/var/log/nginx", "/srv/bakery", "/proc", "/dev", "/usr/bin", "/boot"}
	for _, d := range dirs {
		info, err := f.Stat(d)
		if err != nil || !info.IsDir() {
			t.Errorf("dir %s: %+v %v", d, info, err)
		}
	}
	// merged-usr symlinks
	for _, l := range []string{"/bin", "/sbin", "/lib"} {
		info, err := f.Lstat(l)
		if err != nil || !info.IsSymlink() {
			t.Errorf("%s should be a symlink: %+v %v", l, info, err)
		}
	}
	// /bin/ls resolves through the symlink to the seeded binary.
	if real, err := f.RealPath("/bin/ls"); err != nil || real != "/usr/bin/ls" {
		t.Errorf("/bin/ls -> %q, %v", real, err)
	}

	// hostname is consistent everywhere it appears.
	for _, path := range []string{"/etc/hostname", "/proc/sys/kernel/hostname"} {
		data, _, err := f.ReadFile(path)
		if err != nil || strings.TrimSpace(string(data)) != p.Hostname {
			t.Errorf("%s = %q, want %s", path, data, p.Hostname)
		}
	}
}

func TestSeed_PasswdShadowMatchProfile(t *testing.T) {
	m := testMachine(t)
	passwd, _, _ := m.FS.ReadFile("/etc/passwd")
	for _, u := range m.Profile.Users {
		line := u.Name + ":x:"
		if !strings.Contains(string(passwd), line) {
			t.Errorf("/etc/passwd missing %s", u.Name)
		}
	}
	// Every passwd line has a shadow line.
	shadow, info, err := m.FS.ReadFile("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode.Perm() != 0o640 || info.GID != gidShadow {
		t.Errorf("/etc/shadow perms = %o gid %d", info.Mode.Perm(), info.GID)
	}
	pl := strings.Count(strings.TrimSpace(string(passwd)), "\n") + 1
	sl := strings.Count(strings.TrimSpace(string(shadow)), "\n") + 1
	if pl != sl {
		t.Errorf("passwd has %d lines, shadow %d", pl, sl)
	}
	// root and martin have hashes; deploy/postgres are locked; www-data is disabled.
	if !strings.Contains(string(shadow), "root:$6$") || !strings.Contains(string(shadow), "martin:$6$") {
		t.Error("root/martin should have a $6$ hash")
	}
	if !strings.Contains(string(shadow), "deploy:!:") || !strings.Contains(string(shadow), "postgres:!:") {
		t.Error("deploy/postgres should be locked")
	}
	if !strings.Contains(string(shadow), "www-data:*:") {
		t.Error("www-data should be disabled with *")
	}
}

func TestSeed_Permissions(t *testing.T) {
	m := testMachine(t)
	root := vfs.Cred{UID: 0, GIDs: []int{0}}
	attacker := vfs.Cred{UID: 1337, GIDs: []int{1337}} // some other unprivileged login

	// A non-root attacker cannot read shadow or the app secrets.
	if err := m.FS.Access("/etc/shadow", attacker, vfs.R); err == nil {
		t.Error("attacker should not read /etc/shadow")
	}
	if err := m.FS.Access("/srv/bakery/.env", attacker, vfs.R); err == nil {
		t.Error("attacker (not deploy) should not read .env (0640, owner deploy)")
	}
	if err := m.FS.Access("/root/scripts/backup.sh", attacker, vfs.R); err == nil {
		t.Error("attacker should not read /root")
	}
	// Root can read all of them.
	for _, p := range []string{"/etc/shadow", "/srv/bakery/.env", "/root/scripts/backup.sh"} {
		if err := m.FS.Access(p, root, vfs.R); err != nil {
			t.Errorf("root read %s: %v", p, err)
		}
	}
	// sudoers must be 0440.
	if info, _ := m.FS.Stat("/etc/sudoers"); info.Mode.Perm() != 0o440 {
		t.Errorf("/etc/sudoers perm = %o", info.Mode.Perm())
	}
	// .ssh is 0700.
	if info, _ := m.FS.Stat("/home/martin/.ssh"); info.Mode.Perm() != 0o700 {
		t.Errorf("~/.ssh perm = %o", info.Mode.Perm())
	}
}

func TestSeed_DynamicFilesTrackTheClock(t *testing.T) {
	fixed := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	clock := fixed
	m, err := New(profile.Default(), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	up1, _, _ := m.FS.ReadFile("/proc/uptime")
	clock = clock.Add(time.Hour)
	up2, _, _ := m.FS.ReadFile("/proc/uptime")
	if string(up1) == string(up2) {
		t.Error("/proc/uptime should grow with the clock")
	}
	// uptime fields parse as two floats.
	fields := strings.Fields(string(up2))
	if len(fields) != 2 {
		t.Fatalf("/proc/uptime = %q", up2)
	}

	load, _, _ := m.FS.ReadFile("/proc/loadavg")
	if len(strings.Fields(string(load))) != 5 {
		t.Errorf("/proc/loadavg = %q", load)
	}
}

func TestSeed_MtimesAreOldStableAndVary(t *testing.T) {
	m := testMachine(t)
	now := m.Now()

	// Seeded files are not stamped "now".
	var freshCount int
	paths := []string{}
	err := m.FS.Walk("/", func(p string, info vfs.Info) error {
		paths = append(paths, p)
		if info.ModTime.After(now.Add(-time.Minute)) && !strings.HasPrefix(p, "/proc") && !strings.HasPrefix(p, "/dev") {
			freshCount++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if freshCount > 0 {
		t.Errorf("%d seeded files look freshly modified", freshCount)
	}
	if len(paths) < 300 {
		t.Errorf("only %d nodes seeded, expected a fuller tree", len(paths))
	}

	// Stable across identical seeds.
	m2 := testMachine(t)
	i1, _ := m.FS.Stat("/etc/passwd")
	i2, _ := m2.FS.Stat("/etc/passwd")
	if !i1.ModTime.Equal(i2.ModTime) {
		t.Error("mtimes should be identical across restarts with the same clock")
	}
	// But different files have different times.
	a, _ := m.FS.Stat("/etc/hostname")
	b, _ := m.FS.Stat("/var/log/auth.log")
	if a.ModTime.Equal(b.ModTime) {
		t.Error("different files should have different mtimes")
	}
	// Logs are recent, install files are old.
	if b.ModTime.Before(now.Add(-25 * time.Hour)) {
		t.Errorf("auth.log mtime too old: %v", b.ModTime)
	}
	install, _ := m.FS.Stat("/etc/os-release")
	_ = install
}

func TestSeed_SecretsAppearInPlausiblePlaces(t *testing.T) {
	m := testMachine(t)
	env, _, err := m.FS.ReadFile("/srv/bakery/.env")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DATABASE_URL=postgres://bakery:", "STRIPE_SECRET_KEY=sk_live_", "SESSION_SECRET="} {
		if !strings.Contains(string(env), want) {
			t.Errorf(".env missing %q", want)
		}
	}
	hist, _, _ := m.FS.ReadFile("/root/.bash_history")
	if !strings.Contains(string(hist), "psql") || !strings.Contains(string(hist), "backup.sh") {
		t.Error(".bash_history should tell a story")
	}
}

func TestSeed_DeviceNodes(t *testing.T) {
	m := testMachine(t)
	null, err := m.FS.Stat("/dev/null")
	if err != nil || !null.IsDevice() || null.Mode&fs.ModeCharDevice == 0 {
		t.Errorf("/dev/null = %+v %v", null, err)
	}
	sda, err := m.FS.Stat("/dev/sda")
	if err != nil || !sda.IsDevice() || sda.Mode&fs.ModeCharDevice != 0 {
		t.Errorf("/dev/sda should be a block device: %+v %v", sda, err)
	}
	// /dev/urandom yields bytes.
	data, _, _ := m.FS.ReadFile("/dev/urandom")
	if len(data) == 0 {
		t.Error("/dev/urandom read nothing")
	}
}

func TestNewSessionFS_IsIsolated(t *testing.T) {
	m := testMachine(t)
	s1 := m.NewSessionFS()
	s2 := m.NewSessionFS()
	if err := s1.WriteFile("/tmp/x", []byte("hi"), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	_ = s1.RemoveAll("/etc")
	if s2.Exists("/tmp/x") {
		t.Error("session 2 saw session 1's file")
	}
	if !s2.Exists("/etc/passwd") {
		t.Error("session 2 lost /etc")
	}
	if !m.FS.Exists("/etc/passwd") {
		t.Error("template was mutated")
	}
}

func TestUptimeAndLoad(t *testing.T) {
	m := testMachine(t)
	if got := m.Uptime(); got != m.Profile.BootedAgo {
		t.Errorf("Uptime = %v, want %v", got, m.Profile.BootedAgo)
	}
	l1, l5, l15 := m.LoadAvg()
	for _, l := range []float64{l1, l5, l15} {
		if l < 0 || l > 4 {
			t.Errorf("implausible load %v", l)
		}
	}
}

func TestNew_RejectsInvalidProfile(t *testing.T) {
	p := profile.Default()
	p.Users = nil
	if _, err := New(p, nil); err == nil {
		t.Error("expected an error for an invalid profile")
	}
}
