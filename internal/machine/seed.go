package machine

import "io/fs"

// seed builds the whole template tree. Order matters only in that
// parents must exist before children; each seedX method owns a subtree.
func (m *Machine) seed() error {
	b := &builder{m: m, fs: m.FS}
	b.stamp("/", ageInstall)

	// Ubuntu 22.04 is merged-usr: /bin, /sbin, /lib* are symlinks into /usr.
	for _, d := range []string{"/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/local", "/usr/local/bin",
		"/usr/local/sbin", "/usr/local/lib", "/usr/share", "/usr/include", "/usr/src", "/usr/games", "/usr/libexec"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	b.link("usr/bin", "/bin", ageInstall)
	b.link("usr/sbin", "/sbin", ageInstall)
	b.link("usr/lib", "/lib", ageInstall)
	b.link("usr/lib64", "/lib64", ageInstall)

	for _, d := range []string{"/boot", "/etc", "/home", "/media", "/mnt", "/opt", "/proc", "/run", "/srv", "/sys", "/var", "/dev", "/snap"} {
		b.dir(d, 0o755, 0, 0, ageInstall)
	}
	b.dir("/root", 0o700, 0, 0, ageHome)
	b.dir("/tmp", fs.ModeSticky|0o777, 0, 0, ageRecent)
	b.dir("/var/tmp", fs.ModeSticky|0o777, 0, 0, ageRecent)
	b.dir("/lost+found", 0o700, 0, 0, ageInstall)

	m.seedEtc(b)
	m.seedHomes(b)
	m.seedProc(b)
	m.seedDev(b)
	m.seedBins(b)
	m.seedVar(b)
	m.seedBoot(b)
	b.replay()
	return b.err
}
