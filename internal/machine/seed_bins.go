package machine

import "io/fs"

// binGroups are the groups that own setgid programs in /usr/bin and
// /usr/sbin, with the gids /etc/group gives them.
var binGroups = map[string]int{"root": 0, "tty": 5, "mail": 8, "shadow": 42, "utmp": 43, "_ssh": 112, "crontab": 113}

// seedBins fills /usr/bin, /usr/sbin and /etc/alternatives with exactly
// what the recorded reference box has (refdata/bins.tsv): the same names,
// sizes, modes and symlinks, so which, ls -l and file agree with dpkg about
// what is installed. The files are fake ELF binaries; the shell emulates
// the tools themselves.
func (m *Machine) seedBins(b *builder) {
	for _, e := range reference().bins {
		if e.link {
			b.link(e.target, e.path, ageInstall)
			continue
		}
		b.bin(e.path, e.size)
		if b.err == nil {
			b.failp(e.path, b.fs.Chmod(e.path, fs.FileMode(e.mode&0o777)|unixBits(e.mode)))
			if gid := binGroups[e.group]; gid != 0 {
				b.failp(e.path, b.fs.Chown(e.path, 0, gid))
			}
		}
	}

	b.dir("/usr/lib/openssh", 0o755, 0, 0, ageInstall)
	b.bin("/usr/lib/openssh/sftp-server", 154344)
	b.dir("/usr/lib/systemd", 0o755, 0, 0, ageInstall)
	b.bin("/usr/lib/systemd/systemd", 1620224)
	for _, d := range []string{"/usr/lib/postgresql", "/usr/lib/postgresql/14", "/usr/lib/postgresql/14/bin"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	b.bin("/usr/lib/postgresql/14/bin/postgres", 9182456)

	// A little bit of /usr/share so man and docs are not conspicuously empty.
	for _, d := range []string{"/usr/share/man", "/usr/share/man/man1", "/usr/share/doc", "/usr/share/bash-completion",
		"/usr/share/bash-completion/completions", "/usr/share/vim", "/usr/share/zoneinfo", "/usr/share/keyrings",
		"/usr/share/ca-certificates", "/usr/share/misc", "/usr/lib/file"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	// libmagic's database is binary; reading it shows binary, as it should.
	b.bin("/usr/lib/file/magic.mgc", reference().sizes["magic.mgc"])
	b.fail(b.fs.Chmod("/usr/lib/file/magic.mgc", 0o644))
	b.link("../../lib/file/magic.mgc", "/usr/share/misc/magic.mgc", ageInstall)
}

// unixBits turns the setuid/setgid/sticky bits of a stat mode into Go's.
func unixBits(mode uint32) fs.FileMode {
	var out fs.FileMode
	if mode&0o4000 != 0 {
		out |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		out |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		out |= fs.ModeSticky
	}
	return out
}
