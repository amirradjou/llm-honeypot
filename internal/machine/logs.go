package machine

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The logs under /var/log are generated, not recorded: they have to name this
// box's hostname, users and services and run up to the box's own clock. Every
// event is a pure function of the profile and of the absolute time slot it
// falls in, so two sessions an hour apart see the same history (the later one
// just has more of it), and auth.log agrees with `last`.
//
// Addresses come from the documentation ranges (RFC 5737); nothing about the
// host the honeypot runs on is used.

// Fixed client addresses of the box's admins.
const (
	martinIP = "198.51.100.23" // Martin's home connection
	deployIP = "203.0.113.45"  // the CI runner that deploys the shop
	scanNets = "192.0.2.,198.51.100.,203.0.113."
)

// prng is splitmix64: tiny, deterministic, plenty for log noise.
type prng struct{ x uint64 }

func (m *Machine) rng(parts ...any) *prng {
	h := fnv.New64a()
	_, _ = h.Write([]byte(m.Profile.Hostname))
	for _, p := range parts {
		_, _ = fmt.Fprint(h, "\x00", p)
	}
	return &prng{x: h.Sum64()}
}

func (r *prng) next() uint64 {
	r.x += 0x9E3779B97F4A7C15
	z := r.x
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (r *prng) intn(n int) int { return int(r.next() % uint64(n)) }

func (r *prng) chance(p float64) bool { return float64(r.next()>>11)/float64(1<<53) < p }

func (r *prng) pick(ss []string) string { return ss[r.intn(len(ss))] }

// docIP is a random address from one of the RFC 5737 ranges.
func (r *prng) docIP() string {
	nets := strings.Split(scanNets, ",")
	return nets[r.intn(len(nets))] + strconv.Itoa(1+r.intn(254))
}

// event is one log line before rendering.
type event struct {
	t    time.Time
	seq  int // keeps lines of one exchange in order within a second
	line string
}

type eventLog []event

func (l *eventLog) add(t time.Time, line string) {
	*l = append(*l, event{t: t, seq: len(*l), line: line})
}

// render returns the lines in time order, each followed by a newline.
func (l eventLog) render() []byte {
	sort.SliceStable(l, func(i, j int) bool {
		if !l[i].t.Equal(l[j].t) {
			return l[i].t.Before(l[j].t)
		}
		return l[i].seq < l[j].seq
	})
	var b strings.Builder
	for _, e := range l {
		b.WriteString(e.line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// last is the time of the newest event, or zero.
func (l eventLog) last() time.Time {
	var t time.Time
	for _, e := range l {
		if e.t.After(t) {
			t = e.t
		}
	}
	return t
}

// syslogLine renders the rsyslog traditional format Ubuntu 22.04 uses.
func (m *Machine) syslogLine(t time.Time, tag string, pid int, msg string) string {
	if pid > 0 {
		tag = tag + "[" + strconv.Itoa(pid) + "]"
	}
	return t.Format(time.Stamp) + " " + m.Profile.Hostname + " " + tag + ": " + msg
}

// pidAt is a believable pid for a process started at t: pids climb
// steadily from boot and wrap at the 22.04 pid_max.
func (m *Machine) pidAt(t time.Time, jitter int) int {
	secs := int(t.Sub(m.BootTime) / time.Second)
	if secs < 0 {
		secs = 0
	}
	return 1200 + (secs/11+jitter)%4_190_000
}

// dayStart is local midnight of t's day.
func dayStart(t time.Time) time.Time {
	y, mo, d := t.Date()
	return time.Date(y, mo, d, 0, 0, 0, 0, t.Location())
}

// weekStart is the most recent Sunday midnight: weekly logs rotate then.
func weekStart(t time.Time) time.Time {
	d := dayStart(t)
	return d.AddDate(0, 0, -int(d.Weekday()))
}

// monthStart is midnight on the first of t's month: wtmp rotates then.
func monthStart(t time.Time) time.Time {
	y, mo, _ := t.Date()
	return time.Date(y, mo, 1, 0, 0, 0, 0, t.Location())
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// WtmpBegins is when /var/log/wtmp was last rotated (monthly), as `last`
// reports it.
func (m *Machine) WtmpBegins(now time.Time) time.Time {
	return monthStart(now).Add(12 * time.Second)
}

// Login is one past SSH login by one of the box's admins. auth.log, syslog
// and `last` all read the same list.
type Login struct {
	User       string
	UID        int
	From       string
	Port       int
	TTY        string
	Start, End time.Time
	Session    int // systemd-logind session number
	PID        int // the sshd session process
	Key        string
	Sudo       []string // commands run with sudo, in order
}

// Logins returns the admins' logins that started in [from, to) and had
// ended by to, oldest first. Session numbers count from boot.
func (m *Machine) Logins(from, to time.Time) []Login {
	var all []Login
	day := dayStart(m.BootTime)
	session := 0
	for !day.After(to) {
		var today []Login
		for _, who := range []string{"martin", "deploy"} {
			u := m.Profile.User(who)
			if u == nil {
				continue
			}
			r := m.rng("login", who, day.Format("2006-01-02"))
			var l Login
			switch who {
			case "martin":
				p := 0.45
				if wd := day.Weekday(); wd == time.Saturday || wd == time.Sunday {
					p = 0.1
				}
				if !r.chance(p) {
					continue
				}
				l = Login{From: martinIP, Start: day.Add(time.Duration(8*3600+r.intn(11*3600)) * time.Second)}
				l.End = l.Start.Add(time.Duration(4*60+r.intn(110*60)) * time.Second)
				cmds := []string{"/usr/bin/systemctl status bakery", "/usr/bin/apt update", "/usr/bin/tail -n 100 /var/log/nginx/error.log",
					"/usr/bin/systemctl restart bakery", "/usr/bin/journalctl -u bakery --since today", "/usr/bin/apt list --upgradable",
					"/usr/bin/du -sh /var/backups/bakery", "/usr/bin/fail2ban-client status sshd"}
				for i := r.intn(4); i > 0; i-- {
					l.Sudo = append(l.Sudo, r.pick(cmds))
				}
			case "deploy":
				if !r.chance(0.35) {
					continue
				}
				l = Login{From: deployIP, Start: day.Add(time.Duration(9*3600+r.intn(9*3600)) * time.Second)}
				l.End = l.Start.Add(time.Duration(40+r.intn(200)) * time.Second)
			}
			l.User, l.UID = who, u.UID
			l.Port = 40000 + r.intn(25000)
			l.Key = "ED25519 SHA256:" + base64ish(m.Profile.Hostname+who+"fp", 43)
			if l.Start.Before(m.BootTime) || !l.End.Before(to) {
				continue
			}
			today = append(today, l)
		}
		sort.Slice(today, func(i, j int) bool { return today[i].Start.Before(today[j].Start) })
		for _, l := range today {
			session++
			l.Session = session
			l.PID = m.pidAt(l.Start, 3)
			l.TTY = "pts/0"
			if !l.Start.Before(from) {
				all = append(all, l)
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return all
}

// cronJobs are the scheduled jobs the seeded crontabs define. They drive
// the CRON lines in auth.log and syslog.
type cronJob struct {
	every   int // 10: every ten minutes from offset; 60: at minute offset
	offset  int
	hour    int // -1 for every hour; else the hour (or, with hourDiv, hour%hourDiv)
	hourDiv int
	weekday int // -1 for any
	mday    int // 0 for any
	cmd     string
}

func (m *Machine) cronJobs() []cronJob {
	return []cronJob{
		{every: 10, offset: 0, hour: -1, weekday: -1, cmd: "/usr/bin/curl -s https://hc-ping.com/" + base64ish("hc", 36) + " >/dev/null"},
		{every: 60, offset: 17, hour: -1, weekday: -1, cmd: "   cd / && run-parts --report /etc/cron.hourly"},
		{every: 60, offset: 25, hour: 6, weekday: -1, cmd: "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )"},
		{every: 60, offset: 47, hour: 6, weekday: 0, cmd: "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )"},
		{every: 60, offset: 52, hour: 6, weekday: -1, mday: 1, cmd: "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )"},
		{every: 60, offset: 10, hour: 3, weekday: -1, cmd: "test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r"},
		{every: 60, offset: 30, hour: 3, weekday: 0, cmd: "test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron"},
		{every: 60, offset: 0, hour: 0, hourDiv: 12, weekday: -1, cmd: "test -x /usr/bin/certbot -a \\! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew"},
	}
}

func (j cronJob) due(t time.Time) bool {
	if t.Minute()%j.every != j.offset%j.every || (j.every == 60 && t.Minute() != j.offset) {
		return false
	}
	switch {
	case j.hourDiv > 0:
		if t.Hour()%j.hourDiv != j.hour {
			return false
		}
	case j.hour >= 0 && t.Hour() != j.hour:
		return false
	}
	if j.weekday >= 0 && int(t.Weekday()) != j.weekday {
		return false
	}
	return j.mday == 0 || t.Day() == j.mday
}

// eachMinute calls fn for every whole minute in [from, to).
func eachMinute(from, to time.Time, fn func(t time.Time)) {
	t := from.Truncate(time.Minute)
	if t.Before(from) {
		t = t.Add(time.Minute)
	}
	for ; t.Before(to); t = t.Add(time.Minute) {
		fn(t)
	}
}

// cronRuns calls fn for each cron job run in [from, to), with the run's pid.
func (m *Machine) cronRuns(from, to time.Time, fn func(t time.Time, pid int, cmd string)) {
	jobs := m.cronJobs()
	eachMinute(from, to, func(t time.Time) {
		n := 0
		for _, j := range jobs {
			if j.due(t) {
				t1 := t.Add(time.Duration(m.rng("cronlag", t.Unix()).intn(2)) * time.Second)
				fn(t1, m.pidAt(t1, n), j.cmd)
				n++
			}
		}
	})
}

var botUsers = []string{"admin", "ubuntu", "test", "user", "oracle", "postgres", "git", "ftpuser", "pi", "guest",
	"support", "dev", "server", "minecraft", "hadoop", "deployer", "jenkins", "steam", "teamspeak", "es", "debian",
	"centos", "123", "tomcat", "nagios", "ubnt", "mysql", "www", "user1", "odoo", "sol", "validator", "node", "solana"}

// botAttempts calls fn for every password-guessing connection in [from, to):
// on average one every ten minutes, a third of them for root.
func (m *Machine) botAttempts(from, to time.Time, fn func(t time.Time, r *prng)) {
	const slot = 5 * 60
	for s := from.Unix() / slot; s*slot < to.Unix(); s++ {
		r := m.rng("bot", s)
		for n := r.intn(3); n > 0; n-- {
			t := time.Unix(s*slot+int64(r.intn(slot)), 0).In(from.Location())
			if t.Before(from) || !t.Before(to) {
				continue
			}
			fn(t, r)
		}
	}
}

// authLog renders /var/log/auth.log up to end: it rotates weekly.
func (m *Machine) authLog(end time.Time) (data []byte, mtime time.Time) {
	from := laterOf(weekStart(end), m.BootTime)
	var l eventLog
	host := m.syslogLine
	if !m.BootTime.Before(weekStart(end)) {
		b := m.BootTime
		l.add(b.Add(4*time.Second), host(b.Add(4*time.Second), "systemd-logind", 614, "New seat seat0."))
		l.add(b.Add(4*time.Second), host(b.Add(4*time.Second), "systemd-logind", 614, "Watching system buttons on /dev/input/event0 (Power Button)"))
		l.add(b.Add(5*time.Second), host(b.Add(5*time.Second), "sshd", 672, "Server listening on 0.0.0.0 port 22."))
		l.add(b.Add(5*time.Second), host(b.Add(5*time.Second), "sshd", 672, "Server listening on :: port 22."))
	}
	m.cronRuns(from, end, func(t time.Time, pid int, _ string) {
		l.add(t, host(t, "CRON", pid, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
		l.add(t.Add(time.Second), host(t.Add(time.Second), "CRON", pid, "pam_unix(cron:session): session closed for user root"))
	})
	m.botAttempts(from, end, func(t time.Time, r *prng) {
		ip, port, pid := r.docIP(), 30000+r.intn(35000), m.pidAt(t, 1+r.intn(7))
		at := func(d int) time.Time { return t.Add(time.Duration(d) * time.Second) }
		switch k := r.intn(10); {
		case k < 3: // root, password
			l.add(at(1), host(at(1), "sshd", pid, fmt.Sprintf("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s  user=root", ip)))
			l.add(at(3), host(at(3), "sshd", pid, fmt.Sprintf("Failed password for root from %s port %d ssh2", ip, port)))
			l.add(at(4), host(at(4), "sshd", pid, fmt.Sprintf("Received disconnect from %s port %d:11: Bye Bye [preauth]", ip, port)))
			l.add(at(4), host(at(4), "sshd", pid, fmt.Sprintf("Disconnected from authenticating user root %s port %d [preauth]", ip, port)))
		case k < 8: // an invalid user
			u := r.pick(botUsers)
			l.add(t, host(t, "sshd", pid, fmt.Sprintf("Invalid user %s from %s port %d", u, ip, port)))
			l.add(at(1), host(at(1), "sshd", pid, "pam_unix(sshd:auth): check pass; user unknown"))
			l.add(at(1), host(at(1), "sshd", pid, fmt.Sprintf("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s ", ip)))
			l.add(at(3), host(at(3), "sshd", pid, fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", u, ip, port)))
			l.add(at(4), host(at(4), "sshd", pid, fmt.Sprintf("Received disconnect from %s port %d:11: Bye Bye [preauth]", ip, port)))
			l.add(at(4), host(at(4), "sshd", pid, fmt.Sprintf("Disconnected from invalid user %s %s port %d [preauth]", u, ip, port)))
		case k < 9: // a scanner that only reads the banner
			l.add(t, host(t, "sshd", pid, fmt.Sprintf("Connection closed by %s port %d [preauth]", ip, port)))
		default: // a scanner that does not even finish the key exchange
			l.add(t, host(t, "sshd", pid, "error: kex_exchange_identification: Connection closed by remote host"))
			l.add(t, host(t, "sshd", pid, fmt.Sprintf("Connection closed by %s port %d", ip, port)))
		}
	})
	for _, lg := range m.Logins(from, end) {
		pid, s := lg.PID, lg.Start
		l.add(s, host(s, "sshd", pid, fmt.Sprintf("Accepted publickey for %s from %s port %d ssh2: %s", lg.User, lg.From, lg.Port, lg.Key)))
		l.add(s, host(s, "sshd", pid, fmt.Sprintf("pam_unix(sshd:session): session opened for user %s(uid=%d) by (uid=0)", lg.User, lg.UID)))
		l.add(s, host(s, "systemd-logind", 614, fmt.Sprintf("New session %d of user %s.", lg.Session, lg.User)))
		if lg.User == "martin" {
			// the user manager's own PAM session, as on any 22.04 login
			l.add(s, host(s, "systemd", m.pidAt(s, 5), fmt.Sprintf("pam_unix(systemd-user:session): session opened for user %s(uid=%d) by (uid=0)", lg.User, lg.UID)))
		}
		step := lg.End.Sub(lg.Start) / time.Duration(len(lg.Sudo)+1)
		for i, c := range lg.Sudo {
			t := lg.Start.Add(step * time.Duration(i+1))
			l.add(t, host(t, "sudo", 0, fmt.Sprintf("  %s : TTY=%s ; PWD=/home/%s ; USER=root ; COMMAND=%s", lg.User, lg.TTY, lg.User, c)))
			l.add(t, host(t, "sudo", 0, fmt.Sprintf("pam_unix(sudo:session): session opened for user root(uid=0) by %s(uid=%d)", lg.User, lg.UID)))
			t2 := t.Add(2 * time.Second)
			l.add(t2, host(t2, "sudo", 0, "pam_unix(sudo:session): session closed for user root"))
		}
		e := lg.End
		l.add(e, host(e, "sshd", pid, fmt.Sprintf("Received disconnect from %s port %d:11: disconnected by user", lg.From, lg.Port)))
		l.add(e, host(e, "sshd", pid, fmt.Sprintf("Disconnected from user %s %s port %d", lg.User, lg.From, lg.Port)))
		l.add(e, host(e, "sshd", pid, fmt.Sprintf("pam_unix(sshd:session): session closed for user %s", lg.User)))
		l.add(e, host(e, "systemd-logind", 614, fmt.Sprintf("Session %d logged out. Waiting for processes to exit.", lg.Session)))
		l.add(e, host(e, "systemd-logind", 614, fmt.Sprintf("Removed session %d.", lg.Session)))
	}
	return l.render(), laterOf(l.last(), from)
}

// ufwBlocks calls fn for every packet UFW logs in [from, to): the steady
// background of port scans every internet-facing box sees.
func (m *Machine) ufwBlocks(from, to time.Time, fn func(t time.Time, line string)) {
	p := m.Profile
	ports := []int{23, 445, 3389, 8080, 8443, 5900, 1433, 3306, 6379, 9200, 2375, 5555, 81, 8888, 7547, 37215, 52869, 60001, 2323, 9000}
	const slot = 4 * 60
	for s := from.Unix() / slot; s*slot < to.Unix(); s++ {
		r := m.rng("ufw", s)
		if !r.chance(0.6) {
			continue
		}
		t := time.Unix(s*slot+int64(r.intn(slot)), int64(r.intn(1e9))).In(from.Location())
		if t.Before(from) || !t.Before(to) {
			continue
		}
		up := t.Sub(m.BootTime).Seconds()
		src := r.docIP()
		macs := p.MAC + ":fe:ff:ff:ff:ff:ff:08:00"
		ttl := []int{49, 52, 237, 241, 243, 245, 112}[r.intn(7)]
		msg := fmt.Sprintf("[%12.6f] [UFW BLOCK] IN=%s OUT= MAC=%s SRC=%s DST=%s LEN=%d TOS=0x00 PREC=0x00 TTL=%d ID=%d PROTO=TCP SPT=%d DPT=%d WINDOW=%d RES=0x00 SYN URGP=0 ",
			up, p.Interface, macs, src, p.IPv4, []int{40, 44, 60}[r.intn(3)], ttl, r.intn(65536), 1024+r.intn(64000),
			ports[r.intn(len(ports))], []int{1024, 65535, 29200, 14600}[r.intn(4)])
		fn(t.Truncate(time.Second), m.syslogLine(t, "kernel", 0, msg))
	}
}

// kernLog renders /var/log/kern.log up to end: weekly rotation, and since
// the box booted long before that, nothing but firewall noise.
func (m *Machine) kernLog(end time.Time) ([]byte, time.Time) {
	from := laterOf(weekStart(end), m.BootTime)
	var l eventLog
	m.ufwBlocks(from, end, func(t time.Time, line string) { l.add(t, line) })
	return l.render(), laterOf(l.last(), from)
}

// syslog renders /var/log/syslog up to end: rotated daily, it holds cron,
// systemd timers, the admins' sessions and the kernel's UFW lines for today.
func (m *Machine) syslog(end time.Time) ([]byte, time.Time) {
	from := laterOf(dayStart(end), m.BootTime)
	var l eventLog
	host := m.syslogLine
	sd := func(t time.Time, msg string) { l.add(t, host(t, "systemd", 1, msg)) }
	m.cronRuns(from, end, func(t time.Time, pid int, cmd string) {
		l.add(t, host(t, "CRON", pid, "(root) CMD ("+cmd+")"))
	})
	m.ufwBlocks(from, end, func(t time.Time, line string) { l.add(t, line) })
	// systemd timers: (first run offset from midnight, period, unit description, unit name)
	timers := []struct {
		first, every time.Duration
		desc, unit   string
	}{
		{0, 24 * time.Hour, "Rotate log files", "logrotate.service"},
		{2 * time.Minute, 24 * time.Hour, "Daily man-db regeneration", "man-db.service"},
		{6*time.Hour + 11*time.Minute, 24 * time.Hour, "Daily apt download activities", "apt-daily.service"},
		{6*time.Hour + 38*time.Minute, 24 * time.Hour, "Daily apt upgrade and clean activities", "apt-daily-upgrade.service"},
		{9*time.Hour + 2*time.Minute, 12 * time.Hour, "Message of the Day", "motd-news.service"},
		{5 * time.Minute, 10 * time.Minute, "system activity accounting tool", "sysstat-collect.service"},
		{14*time.Hour + 21*time.Minute, 24 * time.Hour, "Cleanup of Temporary Directories", "systemd-tmpfiles-clean.service"},
		{22*time.Hour + 7*time.Minute, 24 * time.Hour, "Discard unused blocks on filesystems from /etc/fstab", "fstrim.service"},
	}
	day := dayStart(end)
	for _, tm := range timers {
		for t := day.Add(tm.first); t.Before(end); t = t.Add(tm.every) {
			if t.Before(from) {
				continue
			}
			if tm.unit == "fstrim.service" && t.Weekday() != time.Monday {
				continue
			}
			sd(t, "Starting "+tm.desc+"...")
			d := t.Add(time.Duration(1+m.rng("timer", tm.unit, t.Unix()).intn(3)) * time.Second)
			sd(d, tm.unit+": Deactivated successfully.")
			sd(d, "Finished "+tm.desc+".")
			if tm.unit == "apt-daily-upgrade.service" {
				sd(d, tm.unit+": Consumed 2.812s CPU time.")
			}
			if tm.unit == "fstrim.service" {
				l.add(d, host(d, "fstrim", m.pidAt(t, 2), "/boot/efi: 98.2 MiB (102959104 bytes) trimmed on /dev/sda15"))
				l.add(d, host(d, "fstrim", m.pidAt(t, 2), "/: 6.4 GiB (6871269376 bytes) trimmed on /dev/sda1"))
			}
		}
	}
	// snapd's twice-daily refresh check
	for _, h := range []time.Duration{3*time.Hour + 41*time.Minute, 15*time.Hour + 2*time.Minute} {
		t := day.Add(h)
		if !t.Before(from) && t.Before(end) {
			l.add(t, host(t, "snapd", 1580, "storehelpers.go:769: cannot refresh: snap has no updates available: \"core20\", \"lxd\", \"snapd\""))
		}
	}
	for _, lg := range m.Logins(from, end) {
		s, e := lg.Start, lg.End
		uid := strconv.Itoa(lg.UID)
		sd(s, "Created slice User Slice of UID "+uid+".")
		sd(s, "Starting User Runtime Directory /run/user/"+uid+"...")
		sd(s, "Finished User Runtime Directory /run/user/"+uid+".")
		sd(s, "Starting User Manager for UID "+uid+"...")
		sd(s.Add(time.Second), "Started User Manager for UID "+uid+".")
		sd(s.Add(time.Second), fmt.Sprintf("Started Session %d of User %s.", lg.Session, lg.User))
		sd(e, fmt.Sprintf("session-%d.scope: Deactivated successfully.", lg.Session))
		e = e.Add(10 * time.Second)
		sd(e, "Stopping User Manager for UID "+uid+"...")
		sd(e, "user@"+uid+".service: Deactivated successfully.")
		sd(e, "Stopped User Manager for UID "+uid+".")
		sd(e, "Stopping User Runtime Directory /run/user/"+uid+"...")
		sd(e, "run-user-"+uid+".mount: Deactivated successfully.")
		sd(e, "user-runtime-dir@"+uid+".service: Deactivated successfully.")
		sd(e, "Stopped User Runtime Directory /run/user/"+uid+".")
		sd(e, "Removed slice User Slice of UID "+uid+".")
		if lg.User == "deploy" {
			// the CI job restarts the shop after a deploy
			t := s.Add(lg.End.Sub(s) / 2)
			sd(t, "Stopping Hazel Bakery shop (Node.js)...")
			sd(t, "bakery.service: Deactivated successfully.")
			sd(t, "Stopped Hazel Bakery shop (Node.js).")
			sd(t, "Started Hazel Bakery shop (Node.js).")
		}
	}
	return l.render(), laterOf(l.last(), from)
}
