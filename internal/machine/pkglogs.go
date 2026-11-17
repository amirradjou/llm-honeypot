package machine

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// upgradeGroups are packages that Ubuntu updates together (one source
// package each) and that unattended-upgrades installs every few weeks.
// Each must be installed in the recorded package list (a test checks).
var upgradeGroups = [][]string{
	{"libssl3", "openssl"},
	{"curl", "libcurl4", "libcurl3-gnutls"},
	{"vim", "vim-common", "vim-runtime", "vim-tiny", "xxd"},
	{"git", "git-man"},
	{"sudo"},
	{"openssh-client", "openssh-server", "openssh-sftp-server"},
	{"libxml2"},
	{"python3.10", "python3.10-minimal", "libpython3.10", "libpython3.10-minimal", "libpython3.10-stdlib"},
	{"nginx", "nginx-common", "nginx-core"},
	{"libgnutls30"},
	{"libexpat1"},
	{"libsqlite3-0"},
	{"less"},
	{"wget"},
}

var lastNumber = regexp.MustCompile(`(\d+)(\D*)$`)

// previousVersion is the version a security update replaced: the same
// string with its last number one lower ("1ubuntu2.7" -> "1ubuntu2.6").
func previousVersion(v string) (string, bool) {
	loc := lastNumber.FindStringSubmatchIndex(v)
	if loc == nil {
		return "", false
	}
	n, err := strconv.Atoi(v[loc[2]:loc[3]])
	if err != nil || n < 1 {
		return "", false
	}
	return v[:loc[2]] + strconv.Itoa(n-1) + v[loc[3]:], true
}

// dpkgLog renders /var/log/dpkg.log up to end. It rotates monthly, so it
// holds this month's unattended upgrades: on a few mornings, after
// apt-daily-upgrade starts, one or two of the upgrade groups move from the
// previous version to the one dpkg -l shows now.
func (m *Machine) dpkgLog(end time.Time) ([]byte, time.Time) {
	from := monthStart(end)
	var l eventLog
	stamp := func(t time.Time) string { return t.Format("2006-01-02 15:04:05") }
	manDB, _ := m.Package("man-db")
	libcBin, _ := m.Package("libc-bin")
	for d := from; d.Before(end); d = d.AddDate(0, 0, 1) {
		r := m.rng("unattended", d.Format("2006-01-02"))
		if !r.chance(0.3) {
			continue
		}
		t := d.Add(6*time.Hour + 38*time.Minute + time.Duration(30+r.intn(200))*time.Second)
		if !t.Before(end) {
			continue
		}
		groups := [][]string{upgradeGroups[r.intn(len(upgradeGroups))]}
		if r.chance(0.4) {
			groups = append(groups, upgradeGroups[r.intn(len(upgradeGroups))])
		}
		add := func(format string, a ...any) { l.add(t, stamp(t)+" "+fmt.Sprintf(format, a...)) }
		for _, g := range groups {
			type up struct{ name, old, new string }
			var ups []up
			for _, name := range g {
				p, ok := m.Package(name)
				if !ok {
					continue
				}
				prev, ok := previousVersion(p.Version)
				if !ok {
					continue
				}
				ups = append(ups, up{name + ":" + p.Arch, prev, p.Version})
			}
			if len(ups) == 0 {
				continue
			}
			add("startup archives unpack")
			for _, u := range ups {
				add("upgrade %s %s %s", u.name, u.old, u.new)
				add("status half-configured %s %s", u.name, u.old)
				add("status unpacked %s %s", u.name, u.old)
				add("status half-installed %s %s", u.name, u.old)
				t = t.Add(time.Second)
				add("status unpacked %s %s", u.name, u.new)
			}
			add("startup packages configure")
			for _, u := range ups {
				add("configure %s %s <none>", u.name, u.new)
				add("status unpacked %s %s", u.name, u.new)
				add("status half-configured %s %s", u.name, u.new)
				add("status installed %s %s", u.name, u.new)
			}
			add("startup packages configure")
			for _, trig := range []Package{libcBin, manDB} {
				if trig.Name == "" {
					continue
				}
				n := trig.Name + ":" + trig.Arch
				add("trigproc %s %s <none>", n, trig.Version)
				add("status half-configured %s %s", n, trig.Version)
				t = t.Add(time.Second)
				add("status installed %s %s", n, trig.Version)
			}
			t = t.Add(time.Duration(5+r.intn(20)) * time.Second)
		}
	}
	return l.render(), laterOf(l.last(), from)
}
